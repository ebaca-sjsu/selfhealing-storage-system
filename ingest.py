import json
import boto3
import hashlib
import datetime
import urllib.parse
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("selfhealing-object-catalog")

PRIMARY_BUCKET = "selfhealing-primary-dev"
REPLICA_BUCKET = "selfhealing-replica-dev"


def sha256_for_body(body_bytes):
    h = hashlib.sha256()
    h.update(body_bytes)
    return h.hexdigest()


def lambda_handler(event, context):
    """
    Triggered by S3:ObjectCreated events on the primary bucket.
    For each new/updated object:
      - compute checksum & size
      - copy the object to the replica bucket
      - store catalog entry in DynamoDB using the REPLICA versionId
        if available, otherwise use 'latest'.
    """
    now = datetime.datetime.utcnow().isoformat() + "Z"
    processed = 0

    for record in event.get("Records", []):
        s3_info = record.get("s3", {})
        bucket = s3_info.get("bucket", {}).get("name")
        key = urllib.parse.unquote_plus(
            s3_info.get("object", {}).get("key", "")
        )

        if not bucket or not key:
            continue

        # Only handle events for the primary bucket
        if bucket != PRIMARY_BUCKET:
            continue

        try:
            # Get object body from primary
            obj = s3.get_object(Bucket=bucket, Key=key)
            body = obj["Body"].read()
            checksum = sha256_for_body(body)
            size = len(body)

            # Copy to replica bucket
            copy_source = {"Bucket": bucket, "Key": key}
            copy_resp = s3.copy_object(
                Bucket=REPLICA_BUCKET,
                Key=key,
                CopySource=copy_source,
            )

            # IMPORTANT:
            # Only trust the replica VersionId. If replica is not versioned,
            # this will be None and we just treat it as "latest".
            replica_version_id = copy_resp.get("VersionId")
            version_id = replica_version_id or "latest"

            pk = f"{bucket}/{key}"
            sk = f"v#{version_id}"

            item = {
                "pk": pk,
                "sk": sk,
                "bucket": bucket,
                "key": key,
                "checksum": checksum,
                "size": size,
                "versionId": version_id,
                "replicaBucket": REPLICA_BUCKET,
                "lastStatus": "OK",
                "lastVerified": now,
            }

            table.put_item(Item=item)
            processed += 1

        except ClientError as e:
            # Log but don't crash the whole batch
            print(f"Error ingesting {bucket}/{key}: {e}")

    return {"status": "ok", "processed": processed}

