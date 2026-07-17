#!/bin/bash
# ============================================================
# AICGQAF v1.0 - Deploy Lambda Functions
# Koji Dan Seya | TP090490 | CT095-6-M
# ============================================================
# Run AFTER 01_setup_aws.sh
# Usage: bash 02_deploy_lambdas.sh
# ============================================================

set -e
source ./aws_values.env

REGION="ap-southeast-1"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
ROLE_ARN="arn:aws:iam::${ACCOUNT}:role/aicgqaf-lambda-role"
# Use a Windows temp directory that actually exists
WIN_TMP="$(cd "$HOME/AppData/Local/Temp" && pwd)"

# Convert to a Windows-style path for AWS CLI (fileb://)
WIN_TMP_WIN="$(cygpath -w "$WIN_TMP")"
echo ""
echo "=== Deploying Lambda Functions ==="
echo ""

# Wait for IAM role to propagate
echo "Waiting 10s for IAM role to propagate..."
sleep 10

deploy_lambda() {
  NAME=$1
  FILE=$2
  HANDLER=$3
  TIMEOUT=$4

  echo "Deploying: $NAME"

  # Package the function
cd "$WIN_TMP"
rm -rf "pkg_${NAME}" "${NAME}.zip" 2>/dev/null || true
mkdir -p "pkg_${NAME}"
cp "$FILE" "pkg_${NAME}/lambda_function.py"
cd "pkg_${NAME}"
pip install boto3 requests --target . --quiet 2>/dev/null || true
zip -r "../${NAME}.zip" . --quiet
cd "$WIN_TMP"

  # Deploy or update
aws lambda create-function \
  --function-name "$NAME" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler "$HANDLER" \
  --zip-file "fileb://${WIN_TMP_WIN}\\${NAME}.zip" \
  --timeout "$TIMEOUT" \
  --memory-size 256 \
  --environment "Variables={
    S3_BUCKET=${S3_BUCKET},
    DYNAMODB_TABLE=${DYNAMODB_TABLE},
    SQS_QUEUE_URL=${SQS_QUEUE_URL},
    SNS_TOPIC_ARN=${SNS_TOPIC_ARN},
    AWS_REGION_NAME=${REGION}
  }" \
  --region "$REGION" 2>/dev/null || \
aws lambda update-function-code \
  --function-name "$NAME" \
  --zip-file "fileb://${WIN_TMP_WIN}\\${NAME}.zip" \
  --region "$REGION"

  echo "  DONE: $NAME"
}

# Deploy all three Lambda functions
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAMBDA_DIR="$SCRIPT_DIR/../lambda"

deploy_lambda "aicgqaf-intake"    "${LAMBDA_DIR}/intake_lambda.py"  "lambda_function.lambda_handler" 30
deploy_lambda "aicgqaf-gate1"     "${LAMBDA_DIR}/gate1_lambda.py"   "lambda_function.lambda_handler" 60
deploy_lambda "aicgqaf-gate2"     "${LAMBDA_DIR}/gate2_lambda.py"   "lambda_function.lambda_handler" 120

echo ""
echo "=== ALL LAMBDA FUNCTIONS DEPLOYED ==="
echo "NEXT STEP: Push your code to GitHub and open a Pull Request"
echo "DEBUG: LAMBDA_DIR=$LAMBDA_DIR"
echo "DEBUG: intake file=${LAMBDA_DIR}/intake_lambda.py"
ls -la "${LAMBDA_DIR}/intake_lambda.py" || echo "DEBUG: intake_lambda.py NOT FOUND"