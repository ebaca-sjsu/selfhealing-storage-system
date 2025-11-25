import json
import boto3
import hashlib
import datetime
import urllib.parse
import os
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-west-2")
PRIMARY_BUCKET = os.environ.get("PRIMARY_BUCKET")
REPLICA_BUCKET = os.environ.get("REPLICA_BUCKET")
DDB_TABLE = os.environ.get("DDB_TABLE")

s3 = boto3.client("s3", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)
table = dynamodb.Table(DDB_TABLE)


def sha256_for_body(body_bytes):
    h = hashlib.sha256()
    h.update(body_bytes)
    return h.hexdigest()


def lambda_handler(event, context):
    print("Ingest event:", json.dumps(event))

    processed = 0
    now = datetime.datetime.utcnow().isoformat() + "Z"

    for record in event.get("Records", []):
        try:
            bucket = record["s3"]["bucket"]["name"]
            key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
            version_id = record["s3"]["object"].get("versionId")

            get_args = {"Bucket": bucket, "Key": key}
            if version_id:
                get_args["VersionId"] = version_id

            obj = s3.get_object(**get_args)
            body = obj["Body"].read()
            checksum = sha256_for_body(body)
            size = obj.get("ContentLength", len(body))

            # Copy to replica
            copy_source = {"Bucket": bucket, "Key": key}
            if version_id:
                copy_source["VersionId"] = version_id

            s3.copy_object(
                Bucket=REPLICA_BUCKET,
                Key=key,
                CopySource=copy_source,
            )

            pk = f"{PRIMARY_BUCKET}/{key}"
            sk = "meta"

            item = {
                "pk": pk,
                "sk": sk,
                "key": key,
                "versionId": version_id,
                "primaryBucket": PRIMARY_BUCKET,
                "replicaBucket": REPLICA_BUCKET,
                "size": str(size),
                "checksum": checksum,
                "lastStatus": "OK",
                "lastVerified": now,
            }

            table.put_item(Item=item)
            processed += 1

        except ClientError as e:
            print(f"Error ingesting {record}: {e}")

    return {"status": "ok", "processed": processed}

