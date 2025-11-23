#!/usr/bin/env bash
set -euo pipefail

# CONFIG
REGION="us-west-2"

PRIMARY_BUCKET="selfhealing-primary-dev"
REPLICA_BUCKET="selfhealing-replica-dev"
AUDIT_BUCKET="selfhealing-audit-dev"
CONSOLE_BUCKET="selfhealing-console-dev"

DDB_TABLE="selfhealing-object-catalog"

INGEST_ROLE="LambdaIngestRole"
VERIFY_ROLE="LambdaVerifyHealRole"
WEB_API_ROLE="LambdaWebApiRole"

INGEST_FUNC="selfhealing-ingest"
VERIFY_FUNC="selfhealing-verify-heal"
WEB_API_FUNC="selfhealing-web-api"

RULE_NAME="selfhealing-verifier-schedule"
HTTP_API_NAME="selfhealing-http-api"

echo "Using region: $REGION"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "Account ID: $ACCOUNT_ID"

# 1) S3 BUCKETS
echo
echo "Creating S3 buckets (if needed)"

create_bucket() {
  local BUCKET=$1

  if aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
    echo "Bucket $BUCKET already exists"
  else
    if [ "$REGION" = "us-east-1" ]; then
      aws s3api create-bucket --bucket "$BUCKET"
    else
      aws s3api create-bucket \
        --bucket "$BUCKET" \
        --create-bucket-configuration LocationConstraint="$REGION"
    fi
    echo "Created bucket $BUCKET"
  fi

  aws s3api put-bucket-versioning \
    --bucket "$BUCKET" \
    --versioning-configuration Status=Enabled
}

create_bucket "$PRIMARY_BUCKET"
create_bucket "$REPLICA_BUCKET"
create_bucket "$AUDIT_BUCKET"
create_bucket "$CONSOLE_BUCKET"

# 2) DYNAMODB TABLE
echo
echo "Creating DynamoDB table (if needed)"

if aws dynamodb describe-table --table-name "$DDB_TABLE" >/dev/null 2>&1; then
  echo "Table $DDB_TABLE already exists"
else
  aws dynamodb create-table \
    --table-name "$DDB_TABLE" \
    --attribute-definitions \
      AttributeName=pk,AttributeType=S \
      AttributeName=sk,AttributeType=S \
    --key-schema \
      AttributeName=pk,KeyType=HASH \
      AttributeName=sk,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST

  echo "Waiting for table to become ACTIVE..."
  aws dynamodb wait table-exists --table-name "$DDB_TABLE"
fi

# 3) IAM ROLES
echo
echo "Creating IAM roles (if needed)"

TRUST_POLICY_FILE="trust-lambda.json"
if [ ! -f "$TRUST_POLICY_FILE" ]; then
  cat > "$TRUST_POLICY_FILE" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
fi

create_role_if_needed() {
  local ROLE_NAME=$1
  if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
    echo "Role $ROLE_NAME already exists"
  else
    aws iam create-role \
      --role-name "$ROLE_NAME" \
      --assume-role-policy-document file://"$TRUST_POLICY_FILE"

    aws iam attach-role-policy \
      --role-name "$ROLE_NAME" \
      --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

    echo "Created role $ROLE_NAME"
  fi
}

create_role_if_needed "$INGEST_ROLE"
create_role_if_needed "$VERIFY_ROLE"
create_role_if_needed "$WEB_API_ROLE"

# Inline policies
echo
echo "Attaching inline policies"

# Ingest Lambda Policy
INGEST_POLICY_FILE="ingest-policy.json"
cat > "$INGEST_POLICY_FILE" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::$PRIMARY_BUCKET/*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::$REPLICA_BUCKET/*"
    },
    {
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem"],
      "Resource": "arn:aws:dynamodb:$REGION:$ACCOUNT_ID:table/$DDB_TABLE"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name "$INGEST_ROLE" \
  --policy-name "LambdaIngestPolicy" \
  --policy-document file://"$INGEST_POLICY_FILE"

# Verify Lambda Policy
VERIFY_POLICY_FILE="verify-policy.json"
cat > "$VERIFY_POLICY_FILE" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["dynamodb:Scan", "dynamodb:UpdateItem"],
      "Resource": "arn:aws:dynamodb:$REGION:$ACCOUNT_ID:table/$DDB_TABLE"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject","s3:GetObjectVersion","s3:PutObject","s3:CopyObject"],
      "Resource": [
        "arn:aws:s3:::$PRIMARY_BUCKET/*",
        "arn:aws:s3:::$REPLICA_BUCKET/*",
        "arn:aws:s3:::$AUDIT_BUCKET/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::$PRIMARY_BUCKET",
        "arn:aws:s3:::$REPLICA_BUCKET",
        "arn:aws:s3:::$AUDIT_BUCKET"
      ]
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name "$VERIFY_ROLE" \
  --policy-name "LambdaVerifyHealPolicy" \
  --policy-document file://"$VERIFY_POLICY_FILE"

# Web API Lambda Policy (FIXED TO INCLUDE DELETE)
WEB_API_POLICY_FILE="web-api-policy.json"
cat > "$WEB_API_POLICY_FILE" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:Scan",
        "dynamodb:Query",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem"
      ],
      "Resource": "arn:aws:dynamodb:$REGION:$ACCOUNT_ID:table/$DDB_TABLE"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::$PRIMARY_BUCKET",
        "arn:aws:s3:::$PRIMARY_BUCKET/*",
        "arn:aws:s3:::$AUDIT_BUCKET",
        "arn:aws:s3:::$AUDIT_BUCKET/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["lambda:InvokeFunction"],
      "Resource": "arn:aws:lambda:$REGION:$ACCOUNT_ID:function:$VERIFY_FUNC"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name "$WEB_API_ROLE" \
  --policy-name "LambdaWebApiPolicy" \
  --policy-document file://"$WEB_API_POLICY_FILE"

INGEST_ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$INGEST_ROLE"
VERIFY_ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$VERIFY_ROLE"
WEB_API_ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$WEB_API_ROLE"

# 4) PACKAGE LAMBDAS
echo
echo "Packaging Lambda functions"

mkdir -p build

zip -j build/ingest.zip ingest.py >/dev/null
zip -j build/verify_heal.zip verify_heal.py >/dev/null
zip -j build/web_api.zip web_api.py >/dev/null

# 5) CREATE / UPDATE LAMBDAS
echo
echo "Creating/updating Lambda functions"

create_or_update_lambda() {
  local FUNC_NAME=$1
  local ZIP_FILE=$2
  local HANDLER=$3
  local ROLE_ARN=$4
  local ENV_FILE=${5:-}

  if aws lambda get-function --function-name "$FUNC_NAME" >/dev/null 2>&1; then
    echo "Updating code for $FUNC_NAME"
    aws lambda update-function-code \
      --function-name "$FUNC_NAME" \
      --zip-file "fileb://$ZIP_FILE" >/dev/null

    aws lambda wait function-updated --function-name "$FUNC_NAME"

    if [ -n "$ENV_FILE" ]; then
      aws lambda update-function-configuration \
        --function-name "$FUNC_NAME" \
        --role "$ROLE_ARN" \
        --runtime python3.11 \
        --handler "$HANDLER" \
        --timeout 60 \
        --memory-size 256 \
        --environment file://"$ENV_FILE" >/dev/null
    else
      aws lambda update-function-configuration \
        --function-name "$FUNC_NAME" \
        --role "$ROLE_ARN" \
        --runtime python3.11 \
        --handler "$HANDLER" \
        --timeout 60 \
        --memory-size 256 >/dev/null
    fi
  else
    echo "Creating function $FUNC_NAME"
    if [ -n "$ENV_FILE" ]; then
      aws lambda create-function \
        --function-name "$FUNC_NAME" \
        --runtime python3.11 \
        --role "$ROLE_ARN" \
        --handler "$HANDLER" \
        --timeout 60 \
        --memory-size 256 \
        --zip-file "fileb://$ZIP_FILE" \
        --environment file://"$ENV_FILE" \
        --publish >/dev/null
    else
      aws lambda create-function \
        --function-name "$FUNC_NAME" \
        --runtime python3.11 \
        --role "$ROLE_ARN" \
        --handler "$HANDLER" \
        --timeout 60 \
        --memory-size 256 \
        --zip-file "fileb://$ZIP_FILE" \
        --publish >/dev/null
    fi
  fi
}

# Ingest + verify (no env)
create_or_update_lambda "$INGEST_FUNC" "build/ingest.zip" "ingest.lambda_handler" "$INGEST_ROLE_ARN"
create_or_update_lambda "$VERIFY_FUNC" "build/verify_heal.zip" "verify_heal.lambda_handler" "$VERIFY_ROLE_ARN"

INGEST_ARN=$(aws lambda get-function --function-name "$INGEST_FUNC" --query 'Configuration.FunctionArn' --output text)
VERIFY_ARN=$(aws lambda get-function --function-name "$VERIFY_FUNC" --query 'Configuration.FunctionArn' --output text)

# Web API with env vars
WEB_API_ENV_FILE="web-api-env.json"
cat > "$WEB_API_ENV_FILE" <<EOF
{
  "Variables": {
    "PRIMARY_BUCKET": "$PRIMARY_BUCKET",
    "AUDIT_BUCKET": "$AUDIT_BUCKET",
    "DDB_TABLE": "$DDB_TABLE",
    "VERIFY_FUNC": "$VERIFY_FUNC"
  }
}
EOF

create_or_update_lambda "$WEB_API_FUNC" "build/web_api.zip" "web_api.lambda_handler" "$WEB_API_ROLE_ARN" "$WEB_API_ENV_FILE"
WEB_API_ARN=$(aws lambda get-function --function-name "$WEB_API_FUNC" --query 'Configuration.FunctionArn' --output text)

# 6) S3 → INGEST LAMBDA NOTIFICATION
echo
echo "Configuring S3 event notification for ingest Lambda"

aws lambda add-permission \
  --function-name "$INGEST_FUNC" \
  --statement-id "S3InvokeIngest" \
  --action "lambda:InvokeFunction" \
  --principal s3.amazonaws.com \
  --source-arn "arn:aws:s3:::$PRIMARY_BUCKET" \
  --source-account "$ACCOUNT_ID" 2>/dev/null || echo "Permission may already exist"

aws s3api put-bucket-notification-configuration \
  --bucket "$PRIMARY_BUCKET" \
  --notification-configuration "{
    \"LambdaFunctionConfigurations\": [
      {
        \"LambdaFunctionArn\": \"$INGEST_ARN\",
        \"Events\": [\"s3:ObjectCreated:*\"]

      }
    ]
  }"

# 7) EVENTBRIDGE → VERIFY LAMBDA
echo
echo "Configuring EventBridge rule for verify Lambda"

aws events put-rule \
  --name "$RULE_NAME" \
  --schedule-expression "rate(5 minutes)" \
  --state ENABLED >/dev/null

RULE_ARN=$(aws events describe-rule --name "$RULE_NAME" --query 'Arn' --output text)

aws lambda add-permission \
  --function-name "$VERIFY_FUNC" \
  --statement-id "EventBridgeInvokeVerify" \
  --action "lambda:InvokeFunction" \
  --principal events.amazonaws.com \
  --source-arn "$RULE_ARN" 2>/dev/null || echo "Permission may already exist"

aws events put-targets \
  --rule "$RULE_NAME" \
  --targets "Id"="1","Arn"="$VERIFY_ARN" >/dev/null

# 8) HTTP API (API GATEWAY V2) → WEB API LAMBDA
echo
echo "Creating/updating HTTP API"

HTTP_API_ID=$(aws apigatewayv2 get-apis \
  --query "Items[?Name=='$HTTP_API_NAME'].ApiId | [0]" \
  --output text 2>/dev/null || echo "")

if [ -z "$HTTP_API_ID" ] || [ "$HTTP_API_ID" = "None" ]; then
  echo "No existing HTTP API named $HTTP_API_NAME, creating..."
  if [ -f cors.json ]; then
    HTTP_API_ID=$(aws apigatewayv2 create-api \
      --name "$HTTP_API_NAME" \
      --protocol-type HTTP \
      --target "$WEB_API_ARN" \
      --cors-configuration file://cors.json \
      --query "ApiId" \
      --output text)
  else
    HTTP_API_ID=$(aws apigatewayv2 create-api \
      --name "$HTTP_API_NAME" \
      --protocol-type HTTP \
      --target "$WEB_API_ARN" \
      --query "ApiId" \
      --output text)
  fi
else
  echo "HTTP API $HTTP_API_NAME already exists with id $HTTP_API_ID, updating CORS..."
  if [ -f cors.json ]; then
    aws apigatewayv2 update-api \
      --api-id "$HTTP_API_ID" \
      --cors-configuration file://cors.json >/dev/null
  fi
fi

aws lambda add-permission \
  --function-name "$WEB_API_FUNC" \
  --statement-id "HttpApiInvokePermission" \
  --action "lambda:InvokeFunction" \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:$REGION:$ACCOUNT_ID:$HTTP_API_ID/*/*/*" \
  2>/dev/null || echo "Permission for HTTP API may exist"

HTTP_API_ENDPOINT=$(aws apigatewayv2 get-api --api-id "$HTTP_API_ID" --query "ApiEndpoint" --output text)

# 9) CONSOLE UPLOAD
echo
echo "Uploading console index.html to S3"

aws s3 cp index.html "s3://$CONSOLE_BUCKET/index.html"

# 10) CLOUDFRONT (READ-ONLY DETECTION)
echo
echo "hecking for existing CloudFront distribution for console"

ORIGIN_DOMAIN="$CONSOLE_BUCKET.s3.$REGION.amazonaws.com"

CF_DOMAIN=$(aws cloudfront list-distributions \
  --query "DistributionList.Items[?Origins.Items[?DomainName=='$ORIGIN_DOMAIN']].DomainName | [0]" \
  --output text 2>/dev/null || echo "")

if [ -z "$CF_DOMAIN" ] || [ "$CF_DOMAIN" = "None" ]; then
  echo "No existing CloudFront distribution found for origin."
  CF_URL="(none detected)"
else
  echo "Found existing CloudFront distribution: $CF_DOMAIN"
  CF_URL="https://$CF_DOMAIN/"
fi

# OUTPUT
echo
echo "Done. Infrastructure + Lambdas + API + Console deployed."
echo "Primary bucket:      $PRIMARY_BUCKET"
echo "Replica bucket:      $REPLICA_BUCKET"
echo "Audit bucket:        $AUDIT_BUCKET"
echo "Console bucket:      $CONSOLE_BUCKET"
echo "DynamoDB table:      $DDB_TABLE"
echo "Ingest Lambda:       $INGEST_FUNC"
echo "Verify Lambda:       $VERIFY_FUNC"
echo "Web API Lambda:      $WEB_API_FUNC"
echo "HTTP API endpoint:   $HTTP_API_ENDPOINT"
echo "Console CloudFront:  $CF_URL"
echo
echo "Reminder: index.html must use:"
echo "const API_BASE = '$HTTP_API_ENDPOINT';"

