import json
import boto3
import hashlib
import datetime
import os
from botocore.exceptions import ClientError

# Configuration from environment
REGION = os.environ.get("AWS_REGION", "us-west-2")
PRIMARY_BUCKET = os.environ.get("PRIMARY_BUCKET")
REPLICA_BUCKET = os.environ.get("REPLICA_BUCKET")
AUDIT_BUCKET = os.environ.get("AUDIT_BUCKET")
DDB_TABLE = os.environ.get("DDB_TABLE")

s3 = boto3.client("s3", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)
table = dynamodb.Table(DDB_TABLE)


# Helpers Functions

def sha256_for_body(body_bytes: bytes) -> str:
    """Compute hex SHA256 for a bytes buffer."""
    h = hashlib.sha256()
    h.update(body_bytes)
    return h.hexdigest()


def write_audit(bucket: str, key: str, reason: str, details: dict, status: str) -> None:
    """Write a JSON audit record into the audit bucket."""
    now = datetime.datetime.utcnow().isoformat() + "Z"
    report = {
        "timestamp": now,
        "key": key,
        "bucket": bucket,
        "reason": reason,
        "details": details,
        "status": status,
    }
    audit_key = f"reports/{bucket}/{key}/{now}.json"
    s3.put_object(
        Bucket=AUDIT_BUCKET,
        Key=audit_key,
        Body=json.dumps(report).encode("utf-8"),
    )


def is_not_found_error(err: ClientError) -> bool:
    """Return True if the S3 error is a 'not found'-type error."""
    code = err.response.get("Error", {}).get("Code", "")
    return code in ("NoSuchKey", "NotFound", "404")


# Lambda entry

def lambda_handler(event, context):
    print("Verify event:", json.dumps(event))

    scan = table.scan()
    items = scan.get("Items", [])
    processed = 0

    for item in items:
        pk = item["pk"]
        sk = item["sk"]
        key = item.get("key")

        primary_bucket = item.get("primaryBucket", PRIMARY_BUCKET)
        replica_bucket = item.get("replicaBucket", REPLICA_BUCKET)
        expected_checksum = item.get("checksum")
        stored_version_id = item.get("versionId")

        now = datetime.datetime.utcnow().isoformat() + "Z"

        # Case 0: bad row
        if not key:
            print(f"[VERIFY] Skipping item with missing key pk={pk} sk={sk}")
            write_audit(
                primary_bucket or PRIMARY_BUCKET or "UNKNOWN",
                key or "UNKNOWN",
                "MISSING_METADATA",
                {"pk": pk, "sk": sk},
                "FAILED",
            )
            table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression="SET lastVerified = :lv, lastStatus = :st",
                ExpressionAttributeValues={":lv": now, ":st": "FAILED"},
            )
            processed += 1
            continue

        # Case 1: try to read from PRIMARY
        try:
            obj = s3.get_object(Bucket=primary_bucket, Key=key)
            body = obj["Body"].read()

            # If we have a checksum, verify it
            if expected_checksum:
                actual_checksum = sha256_for_body(body)
                if actual_checksum != expected_checksum:
                    # Corruption: restore from replica
                    print(
                        f"[VERIFY] Checksum mismatch for {key}: "
                        f"expected={expected_checksum}, actual={actual_checksum}"
                    )
                    try:
                        copy_source = {"Bucket": replica_bucket, "Key": key}
                        s3.copy_object(
                            Bucket=primary_bucket,
                            Key=key,
                            CopySource=copy_source,
                        )
                        status = "RESTORED_FROM_REPLICA"
                        write_audit(
                            primary_bucket,
                            key,
                            "CHECKSUM_MISMATCH",
                            {
                                "expected": expected_checksum,
                                "actual": actual_checksum,
                                "storedVersionId": stored_version_id,
                            },
                            status,
                        )
                    except ClientError as ce2:
                        print(f"[VERIFY] FAILED to heal checksum for {key}: {ce2}")
                        status = "FAILED"
                        write_audit(
                            primary_bucket,
                            key,
                            "CHECKSUM_MISMATCH",
                            {
                                "expected": expected_checksum,
                                "actual": actual_checksum,
                                "recoveryError": str(ce2),
                                "storedVersionId": stored_version_id,
                            },
                            status,
                        )
                    # Update Dynamo and move on for this item
                    table.update_item(
                        Key={"pk": pk, "sk": sk},
                        UpdateExpression="SET lastVerified = :lv, lastStatus = :st",
                        ExpressionAttributeValues={":lv": now, ":st": status},
                    )
                    print(f"[VERIFY] Completed {key}: status={status}")
                    processed += 1
                    continue

            # If we got here, object exists and checksum is fine
            status = "OK"
            table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression="SET lastVerified = :lv, lastStatus = :st",
                ExpressionAttributeValues={":lv": now, ":st": status},
            )
            print(f"[VERIFY] Completed {key}: status={status}")
            processed += 1
            continue

        except ClientError as e:
            # Case 2: error reading from PRIMARY
            if is_not_found_error(e):
                print(f"[VERIFY] {key} missing from primary, attempting restore")
                try:
                    copy_source = {"Bucket": replica_bucket, "Key": key}
                    s3.copy_object(
                        Bucket=primary_bucket,
                        Key=key,
                        CopySource=copy_source,
                    )
                    status = "RESTORED_FROM_REPLICA"
                    write_audit(
                        primary_bucket,
                        key,
                        "MISSING_OBJECT",
                        {
                            "error": str(e),
                            "storedVersionId": stored_version_id,
                        },
                        status,
                    )
                except ClientError as e2:
                    print(f"[VERIFY] FAILED to restore {key} from replica: {e2}")
                    status = "FAILED"
                    write_audit(
                        primary_bucket,
                        key,
                        "MISSING_OBJECT",
                        {
                            "error": str(e),
                            "recoveryError": str(e2),
                            "storedVersionId": stored_version_id,
                        },
                        status,
                    )
            else:
                # Non-404 error talking to S3
                print(f"[VERIFY] Error reading {key} from primary: {e}")
                status = "FAILED"
                write_audit(
                    primary_bucket,
                    key,
                    "S3_GET_ERROR",
                    {
                        "error": str(e),
                        "storedVersionId": stored_version_id,
                    },
                    status,
                )

            # In all error paths above, persist final status and continue
            table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression="SET lastVerified = :lv, lastStatus = :st",
                ExpressionAttributeValues={":lv": now, ":st": status},
            )
            print(f"[VERIFY] Completed {key}: status={status}")
            processed += 1
            continue

    return {"status": "ok", "processed": processed}

