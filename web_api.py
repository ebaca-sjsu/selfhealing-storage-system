import json
import base64
import boto3
import urllib.parse
import os

REGION = os.environ.get("AWS_REGION", "us-west-2")
PRIMARY_BUCKET = os.environ.get("PRIMARY_BUCKET")
AUDIT_BUCKET = os.environ.get("AUDIT_BUCKET")
DDB_TABLE = os.environ.get("DDB_TABLE")
VERIFY_FUNC = os.environ.get("VERIFY_FUNC")

dynamodb = boto3.resource("dynamodb", region_name=REGION)
table = dynamodb.Table(DDB_TABLE)
s3 = boto3.client("s3", region_name=REGION)
lambda_client = boto3.client("lambda", region_name=REGION)


def response(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(body, default=str),
    }


def list_objects():
    items = []
    resp = table.scan()
    for item in resp.get("Items", []):
        items.append(
            {
                "key": item["key"],
                "versionId": item.get("versionId"),
                "lastStatus": item.get("lastStatus"),
                "lastVerified": item.get("lastVerified"),
                "size": item.get("size"),
            }
        )
    return response(200, {"objects": items})


def upload_object(event):
    body = json.loads(event["body"])
    key = body["key"]
    content_b64 = body["content"]
    data = base64.b64decode(content_b64.encode("utf-8"))
    s3.put_object(Bucket=PRIMARY_BUCKET, Key=key, Body=data)
    return response(200, {"uploaded": key})


def delete_object(event):
    body = json.loads(event["body"])
    key = body["key"]
    s3.delete_object(Bucket=PRIMARY_BUCKET, Key=key)
    return response(200, {"deleted": key})


def run_verify(_event):
    resp = lambda_client.invoke(
        FunctionName=VERIFY_FUNC,
        InvocationType="RequestResponse",
    )
    try:
        payload = resp["Payload"].read().decode("utf-8")
        data = json.loads(payload)
    except Exception:
        data = {"raw": payload}
    return response(200, {"verify": data})


def list_audits(event):
    """
    List audit log objects for a given file and include the parsed
    JSON content of each audit entry.

    Frontend sends: GET /audits?key=<file_name>
    """
    qs = event.get("rawQueryString", "")
    params = urllib.parse.parse_qs(qs)
    file_name = params.get("key", [""])[0]

    if not file_name:
        return response(400, {"error": "Missing 'key' query parameter"})

    # Audit objects are stored like:
    # reports/<primary-bucket>/<file_name>/<timestamp>.json
    prefix = f"reports/{PRIMARY_BUCKET}/{file_name}/"

    s3_resp = s3.list_objects_v2(Bucket=AUDIT_BUCKET, Prefix=prefix)
    contents = s3_resp.get("Contents", [])

    audits = []

    for obj in contents:
        obj_key = obj["Key"]

        # Read the JSON report from S3
        body_bytes = s3.get_object(
            Bucket=AUDIT_BUCKET,
            Key=obj_key,
        )["Body"].read()

        try:
            report = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            # Fallback: return raw text if not valid JSON
            report = {
                "raw": body_bytes.decode("utf-8", errors="replace"),
            }

        audits.append(
            {
                "key": obj_key,
                "size": obj["Size"],
                "lastModified": obj["LastModified"].isoformat(),
                "report": report,
            }
        )

    return response(200, {"audits": audits})


def lambda_handler(event, context):
    method = event["requestContext"]["http"]["method"]
    path = event["requestContext"]["http"]["path"]

    if method == "OPTIONS":
        return response(200, {})

    if method == "GET" and path.endswith("/objects"):
        return list_objects()

    if method == "POST" and path.endswith("/upload"):
        return upload_object(event)

    if method == "POST" and path.endswith("/delete"):
        return delete_object(event)

    if method == "POST" and path.endswith("/verify"):
        return run_verify(event)

    if method == "GET" and path.endswith("/audits"):
        return list_audits(event)

    return response(404, {"error": f"{method} {path} not found"})

