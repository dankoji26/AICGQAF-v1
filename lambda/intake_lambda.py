"""
AICGQAF v1.0 - Intake Lambda Function
Koji Dan Seya | TP090490 | CT095-6-M

Triggered by GitHub Actions webhook.
Creates review record in DynamoDB and saves PR diff to S3.
"""
import json
import os
import uuid
import boto3
from datetime import datetime, timezone

S3_BUCKET      = os.environ["S3_BUCKET"]
DYNAMODB_TABLE = os.environ["DYNAMODB_TABLE"]
AWS_REGION     = os.environ.get("AWS_REGION_NAME", "ap-southeast-1")

s3       = boto3.client("s3",       region_name=AWS_REGION)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)

def lambda_handler(event, context):
    """
    Receives PR data from GitHub Actions,
    creates a review record in DynamoDB,
    and stores the diff in S3.
    """
    body = json.loads(event.get("body", "{}")) if isinstance(event.get("body"), str) else event

    review_id  = str(uuid.uuid4())
    pr_number  = body.get("pr_number", 0)
    repo_url   = body.get("repo_url", "")
    language   = body.get("language", "python")
    diff_url   = body.get("diff_url", "")
    author     = body.get("author", "unknown")
    pr_title   = body.get("pr_title", "")
    timestamp  = datetime.now(timezone.utc).isoformat()

    # Save diff content to S3
    diff_content = body.get("diff_content", "")
    if diff_content:
        s3_key = f"reviews/{review_id}/pr.diff"
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=diff_content.encode(),
            ContentType="text/plain"
        )

    # Create DynamoDB record
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.put_item(Item={
        "review_id":   review_id,
        "status":      "RECEIVED",
        "pr_number":   pr_number,
        "repo_url":    repo_url,
        "language":    language,
        "author":      author,
        "pr_title":    pr_title,
        "created_at":  timestamp,
        "updated_at":  timestamp,
        "framework":   "AICGQAF",
        "version":     "1.0"
    })

    print(f"[Intake] Review created: {review_id} | PR #{pr_number}")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "review_id": review_id,
            "status":    "RECEIVED",
            "pr_number": pr_number,
            "estimated_completion_minutes": 5
        })
    }
