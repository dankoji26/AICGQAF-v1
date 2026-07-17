#!/bin/bash
# ============================================================
# AICGQAF v1.0 - AWS Infrastructure Setup
# Koji Dan Seya | TP090490 | CT095-6-M
# ============================================================
# HOW TO RUN:
#   1. Install AWS CLI: https://aws.amazon.com/cli/
#   2. Open terminal and run: aws configure
#      Enter: Access Key, Secret Key, Region=ap-southeast-1, json
#   3. Run: bash 01_setup_aws.sh
# ============================================================

set -e
REGION="ap-southeast-1"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
PROJECT="aicgqaf"
BUCKET="${PROJECT}-artifacts-${ACCOUNT}"

echo ""
echo "=== AICGQAF v1.0 - AWS Infrastructure Setup ==="
echo "Account : $ACCOUNT"
echo "Region  : $REGION"
echo ""

echo "[1/5] S3 Bucket: $BUCKET"
aws s3api create-bucket \
  --bucket "$BUCKET" \
  --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null || true
aws s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled
aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
echo "  DONE"

echo "[2/5] DynamoDB Table: ${PROJECT}-reviews"
aws dynamodb create-table \
  --table-name "${PROJECT}-reviews" \
  --attribute-definitions AttributeName=review_id,AttributeType=S \
  --key-schema AttributeName=review_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region "$REGION" 2>/dev/null || true
aws dynamodb wait table-exists \
  --table-name "${PROJECT}-reviews" --region "$REGION"
echo "  DONE"

echo "[3/5] SQS FIFO Queue..."
SQS_URL=$(aws sqs create-queue \
  --queue-name "${PROJECT}-reviews.fifo" \
  --attributes '{"FifoQueue":"true","ContentBasedDeduplication":"true","VisibilityTimeout":"1800"}' \
  --region "$REGION" --query QueueUrl --output text 2>/dev/null || \
  aws sqs get-queue-url --queue-name "${PROJECT}-reviews.fifo" \
  --region "$REGION" --query QueueUrl --output text)
echo "  DONE: $SQS_URL"

echo "[4/5] SNS Topic..."
SNS_ARN=$(aws sns create-topic \
  --name "${PROJECT}-notifications" \
  --region "$REGION" --query TopicArn --output text)
echo "  DONE: $SNS_ARN"

echo "[5/5] IAM Lambda Role..."
aws iam create-role \
  --role-name "${PROJECT}-lambda-role" \
  --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  2>/dev/null || true

for POLICY in \
  "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" \
  "arn:aws:iam::aws:policy/AmazonS3FullAccess" \
  "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess" \
  "arn:aws:iam::aws:policy/AmazonSQSFullAccess" \
  "arn:aws:iam::aws:policy/AmazonSNSFullAccess"; do
  aws iam attach-role-policy \
    --role-name "${PROJECT}-lambda-role" \
    --policy-arn "$POLICY" 2>/dev/null || true
done
ROLE_ARN="arn:aws:iam::${ACCOUNT}:role/${PROJECT}-lambda-role"
echo "  DONE: $ROLE_ARN"

cat > ./aws_values.env << ENVEOF
# AICGQAF AWS Values - DO NOT COMMIT TO GIT
export AWS_REGION="${REGION}"
export S3_BUCKET="${BUCKET}"
export DYNAMODB_TABLE="${PROJECT}-reviews"
export SQS_QUEUE_URL="${SQS_URL}"
export SNS_TOPIC_ARN="${SNS_ARN}"
export LAMBDA_ROLE_ARN="${ROLE_ARN}"
ENVEOF

echo ""
echo "=== ALL DONE - COPY THESE TO GITHUB SECRETS ==="
echo "AWS_REGION     = $REGION"
echo "S3_BUCKET      = $BUCKET"
echo "DYNAMODB_TABLE = ${PROJECT}-reviews"
echo "SQS_QUEUE_URL  = $SQS_URL"
echo "SNS_TOPIC_ARN  = $SNS_ARN"
echo ""
echo "NEXT STEP: Run bash 02_deploy_lambdas.sh"
