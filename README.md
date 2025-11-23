# Self-Healing Storage System

A simple serverless storage system that automatically:
- Replicates S3 uploads to a backup bucket  
- Detects missing/corrupted files  
- Restores them from the replica  
- Logs all repair events  
- Provides a small web UI to test everything

Built with AWS Lambda, S3, DynamoDB, API Gateway, EventBridge, and CloudFront.

---
build.sh          # Deploys everything
ingest.py         # Ingest + replicate
verify_heal.py    # Verify + heal
web_api.py        # API handler
index.html        # Web console UI

# Deploy (One Command)

1. Clone this repo  
2. Make script executable:  
chmod +x build.sh
3. Run the deploy script:  
./build.sh
The script creates all AWS resources (buckets, Lambdas, DynamoDB, API, console UI).

At the end it prints your CloudFront console URL:
Console CloudFront: https://xxxxx.cloudfront.net/

Open that in your browser.

---

# How to Use

In the UI you can:
- Upload files  
- Delete files (simulate corruption)  
- Run Verify (auto-heals files)  
- Refresh object catalog  
- Load audit logs  


Example audit entry:
json
{ "reason": "MISSING_OBJECT", "status": "RESTORED_FROM_REPLICA" }

