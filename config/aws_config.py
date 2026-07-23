"""
AICGQAF v1.0 - Test PR File 2: Hard-coded Credentials
======================================================
This file is intentionally vulnerable for testing the pipeline.
Expected result: Layer 1 FAIL — CWE-798 auto-rejected.
"""
import boto3

# VULNERABILITY: Hard-coded AWS credentials (CWE-798)
# AI-generated code embedding secrets as string literals
AWS_REGION            = "ap-southeast-1"
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
S3_BUCKET             = "my-production-bucket"

def get_s3_client():
    return boto3.client("s3",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

def upload_file(file_path, key):
    get_s3_client().upload_file(file_path, S3_BUCKET, key)
    return f"Uploaded {key}"
