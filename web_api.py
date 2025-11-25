import json
import base64
import boto3
import urllib.parse
import os
from decimal import Decimal
from botocore.exceptions import ClientError

# Environment variables
REGION = os.environ.get("AWS_REGION", "us-west-2")
PRIMARY_BUCKET = os.environ.get("PRIMARY_BUCKET")
REPLICA_BUCKET = os.environ.get("REPLICA_BUCKET") 
AUDIT_BUCKET = os.environ.get("AUDIT_BUCKET")
DDB_TABLE = os.environ.get("DDB_TABLE")
VERIFY_FUNC = os.environ.get("VERIFY_FUNC")

dynamodb = boto3.resource("dynamodb", region_name=REGION)
table = dynamodb.Table(DDB_TABLE)
s3 = boto3.client("s3", region_name=REGION)
lambda_client = boto3.client("lambda", region_name=REGION)


def _json_default(o):
    if isinstance(o, Decimal):
        return str(o)
    raise TypeError(f"Object {type(o)} not JSON serializable")


def response(status, body):
    """Standard JSON response with CORS."""
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(body, default=_json_default),
    }


def _parse_query(event):
    """Parse query params from HTTP API v2 or REST v1."""
    if "rawQueryString" in event:
        raw = event.get("rawQueryString") or ""
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
    return event.get("queryStringParameters") or {}


def _parse_body(event):
    """Parse request body from JSON or form-encoded.

    - If body is empty -> {}
    - If body is already a dict -> return as-is
    - First try JSON
    - If JSON fails, fall back to key=value&... parsing
    """
    raw = event.get("body")
    if not raw:
        return {}

    if isinstance(raw, dict):
        return raw

    # Try JSON first
    try:
        return json.loads(raw)
    except Exception:
        # Fallback: application/x-www-form-urlencoded style
        qs = urllib.parse.parse_qs(raw)
        return {k: v[0] for k, v in qs.items()}


def list_objects():
    """Deduplicate by key, return latest version entry."""
    scan = table.scan()
    items = scan.get("Items", [])

    by_key = {}

    for item in items:
        key = item.get("key")
        if not key:
            continue

        if key not in by_key:
            by_key[key] = item
        else:
            # Keep the one with latest lastVerified timestamp
            old = by_key[key].get("lastVerified") or ""
            new = item.get("lastVerified") or ""
            if new > old:
                by_key[key] = item

    result = []
    for item in by_key.values():
        result.append(
            {
                "key": item.get("key"),
                "versionId": item.get("versionId"),
                "lastStatus": item.get("lastStatus"),
                "lastVerified": item.get("lastVerified"),
                "size": item.get("size"),
            }
        )

    return response(200, {"objects": result})


def upload_object(event):
    """POST /upload – expects {key, content(base64)}."""
    if not PRIMARY_BUCKET:
        return response(
            500,
            {"error": "PRIMARY_BUCKET env var is not set.", "PRIMARY_BUCKET": PRIMARY_BUCKET},
        )

    body = _parse_body(event)
    key = body.get("key")
    content_b64 = body.get("content")

    if not key or content_b64 is None:
        return response(400, {"error": "Both 'key' and 'content' are required."})

    # Decode
    try:
        data = base64.b64decode(content_b64.encode("utf-8"))
    except Exception as e:
        return response(
            400,
            {
                "error": "Content is not valid base64.",
                "message": str(e),
            },
        )

    # Put to S3 with broad error handling
    try:
        s3.put_object(Bucket=PRIMARY_BUCKET, Key=key, Body=data)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        return response(
            500,
            {
                "error": "Failed to upload object to S3 (ClientError).",
                "key": key,
                "bucket": PRIMARY_BUCKET,
                "s3ErrorCode": code,
                "message": str(e),
            },
        )
    except Exception as e:
        # This will catch ParamValidationError 
        return response(
            500,
            {
                "error": "Failed to upload object to S3 (non-ClientError).",
                "key": key,
                "bucket": PRIMARY_BUCKET,
                "exceptionType": type(e).__name__,
                "message": str(e),
            },
        )

    return response(200, {"uploaded": key})


def delete_object(event):
    """POST /delete – expects {key}."""
    if not PRIMARY_BUCKET:
        return response(
            500,
            {"error": "PRIMARY_BUCKET env var is not set.", "PRIMARY_BUCKET": PRIMARY_BUCKET},
        )

    body = _parse_body(event)
    key = body.get("key")

    if not key:
        return response(400, {"error": "Missing 'key' in body."})

    try:
        s3.delete_object(Bucket=PRIMARY_BUCKET, Key=key)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        return response(
            500,
            {
                "error": "Failed to delete object from S3 (ClientError).",
                "key": key,
                "bucket": PRIMARY_BUCKET,
                "s3ErrorCode": code,
                "message": str(e),
            },
        )
    except Exception as e:
        return response(
            500,
            {
                "error": "Failed to delete object from S3 (non-ClientError).",
                "key": key,
                "bucket": PRIMARY_BUCKET,
                "exceptionType": type(e).__name__,
                "message": str(e),
            },
        )

    return response(200, {"deleted": key})


def run_verify(event):
    """POST /verify – invokes verify-heal Lambda."""
    try:
        resp = lambda_client.invoke(
            FunctionName=VERIFY_FUNC,
            InvocationType="RequestResponse",
        )
        payload = resp.get("Payload")
        if not payload:
            return response(500, {"error": "Verify function returned no payload."})

        raw = payload.read().decode("utf-8")
        try:
            data = json.loads(raw)
        except Exception:
            data = {"raw": raw}

        return response(200, {"verify": data})
    except Exception as e:
        return response(
            500,
            {"error": "Failed to invoke verify function.", "message": str(e)},
        )


def list_audits(event):
    """GET /audits?key=... – list audit entries for a file."""
    params = _parse_query(event)
    key = params.get("key")

    if not key:
        return response(400, {"error": "Missing 'key' query parameter."})

    prefix = f"reports/{PRIMARY_BUCKET}/{key}/"

    try:
        out = s3.list_objects_v2(Bucket=AUDIT_BUCKET, Prefix=prefix)
        contents = out.get("Contents", [])
    except Exception as e:
        return response(
            500,
            {"error": "Failed to list audit objects.", "message": str(e)},
        )

    audits = []
    for obj in contents:
        obj_key = obj["Key"]

        try:
            body = s3.get_object(Bucket=AUDIT_BUCKET, Key=obj_key)["Body"].read()
            try:
                report = json.loads(body.decode("utf-8"))
            except Exception:
                report = {"raw": body.decode("utf-8", errors="replace")}
        except Exception as e:
            report = {"error": "Failed to read audit object.", "message": str(e)}

        audits.append(
            {
                "key": obj_key,
                "size": obj["Size"],
                "lastModified": obj["LastModified"].isoformat(),
                "report": report,
            }
        )

    return response(200, {"audits": audits})


def get_file_content(event):
    """GET /file?key=name[&versionId=v] – returns text or base64."""
    params = _parse_query(event)
    key = params.get("key")
    version_id = params.get("versionId")

    if not key:
        return response(400, {"error": "Missing 'key' query parameter."})

    args = {"Bucket": PRIMARY_BUCKET, "Key": key}
    if version_id:
        args["VersionId"] = version_id

    try:
        obj = s3.get_object(**args)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "NoSuchVersion", "404"):
            return response(
                404,
                {
                    "error": "Object not found.",
                    "key": key,
                    "versionId": version_id,
                    "s3ErrorCode": code,
                },
            )
        # Other S3 errors
        return response(
            500,
            {
                "error": "S3 get_object failed (ClientError).",
                "key": key,
                "versionId": version_id,
                "s3ErrorCode": code,
                "message": str(e),
            },
        )
    except Exception as e:
        return response(
            500,
            {
                "error": "S3 get_object failed (non-ClientError).",
                "key": key,
                "versionId": version_id,
                "exceptionType": type(e).__name__,
                "message": str(e),
            },
        )

    body = obj["Body"].read()

    result = {
        "key": key,
        "versionId": obj.get("VersionId") or version_id,
    }

    try:
        text = body.decode("utf-8")
        result.update({"encoding": "utf-8", "text": text})
    except UnicodeDecodeError:
        result.update(
            {
                "encoding": "base64",
                "contentBase64": base64.b64encode(body).decode("ascii"),
            }
        )

    return response(200, result)

def lambda_handler(event, context):
    # Safe logging
    try:
        print("Incoming event:", json.dumps(event, default=_json_default))
    except Exception:
        print("Incoming event (unserializable)")

    method = None
    path = None

    rc = event.get("requestContext") or {}
    if "http" in rc:
        http = rc["http"]
        method = http.get("method")
        path = http.get("path")
    else:
        method = event.get("httpMethod")
        path = event.get("path")

    # OPTIONS CORS 
    if (method or "").upper() == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            },
            "body": "",
        }

    if not method or not path:
        return response(400, {"error": "Unable to determine HTTP method/path."})

    # Routes
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

    if method == "GET" and path.endswith("/file"):
        return get_file_content(event)

    return response(404, {"error": f"{method} {path} not found."})

