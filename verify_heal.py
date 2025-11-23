import json
import boto3
import hashlib
import datetime
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("selfhealing-object-catalog")

AUDIT_BUCKET = "selfhealing-audit-dev"


def sha256_for_body(body_bytes):
    h = hashlib.sha256()
    h.update(body_bytes)
    return h.hexdigest()


def lambda_handler(event, context):
    scan_kwargs = {}
    processed = 0

    while True:
        response = table.scan(**scan_kwargs)
        items = response.get("Items", [])

        for item in items:
            verify_item(item)
            processed += 1

        if "LastEvaluatedKey" not in response:
            break

        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    return {"status": "ok", "processed": processed}


def verify_item(item):
    bucket = item["bucket"]
    key = item["key"]
    expected = item["checksum"]
    pk = item["pk"]
    sk = item["sk"]

    now = datetime.datetime.utcnow().isoformat() + "Z"

    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read()
        actual = sha256_for_body(body)

        if actual == expected:
            table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression="SET lastVerified = :lv, lastStatus = :st",
                ExpressionAttributeValues={":lv": now, ":st": "OK"},
            )
            return
        else:
            heal_item(
                item,
                reason="CHECKSUM_MISMATCH",
                details={"expected": expected, "actual": actual}
            )

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            heal_item(
                item,
                reason="MISSING_OBJECT",
                details={"error": str(e)}
            )
        else:
            raise


def heal_item(item, reason, details):
    bucket = item["bucket"]
    key = item["key"]
    replica = item.get("replicaBucket")
    version_id = item.get("versionId")
    pk = item["pk"]
    sk = item["sk"]

    now = datetime.datetime.utcnow().isoformat() + "Z"

    recovery_status = "FAILED"

    try:
        if replica:
            # Correct version-aware copy source
            copy_source = {"Bucket": replica, "Key": key}
            if version_id and version_id != "latest":
                copy_source["VersionId"] = version_id

            s3.copy_object(
                Bucket=bucket,
                Key=key,
                CopySource=copy_source
            )

            recovery_status = "RESTORED_FROM_REPLICA"

    except Exception as e:
        details["recoveryError"] = str(e)

    # Write audit record
    report = {
        "timestamp": now,
        "key": key,
        "bucket": bucket,
        "reason": reason,
        "details": details,
        "status": recovery_status
    }

    audit_key = f"reports/{bucket}/{key}/{now}.json"
    s3.put_object(
        Bucket=AUDIT_BUCKET,
        Key=audit_key,
        Body=json.dumps(report).encode("utf-8")
    )

    # Update DynamoDB entry
    table.update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression="SET lastVerified = :lv, lastStatus = :st",
        ExpressionAttributeValues={":lv": now, ":st": recovery_status},
    )

