# AICGQAF v1.0 — Complete Deployment Guide
## Koji Dan Seya | TP090490 | CT095-6-M

---

## YOUR FOLDER STRUCTURE

After setting up, your project should look like this:

```
AICGQAF/
├── .github/
│   └── workflows/
│       └── aicgqaf.yml          ← Copy from github/aicgqaf.yml
├── scripts/
│   ├── layer1_static_analysis.py
│   ├── layer2_ai_review.py
│   └── final_decision.py
├── aws/
│   ├── 01_setup_aws.sh
│   ├── 02_deploy_lambdas.sh
│   └── aws_values.env           ← Created automatically
├── lambda/
│   ├── intake_lambda.py
│   ├── gate1_lambda.py
│   └── gate2_lambda.py
├── config/
│   └── aicgqaf-config.yml
├── test_prs/
│   ├── test_sqli_vulnerable.py
│   ├── test_creds_vulnerable.py
│   ├── test_idor_vulnerable.py
│   └── test_clean_code.py
├── layer3_dashboard.html
└── README.md
```

---

## STEP-BY-STEP DEPLOYMENT

---

### STEP 1 — Install Required Tools (10 minutes)

Open VS Code terminal (Ctrl + backtick):

**Install AWS CLI:**
- Windows: https://awscli.amazonaws.com/AWSCLIV2.msi
- Mac: brew install awscli
- Linux: sudo apt install awscli

**Install Python packages:**
```bash
pip install boto3 requests bandit
```

**Verify AWS CLI:**
```bash
aws --version
```

---

### STEP 2 — Configure AWS Credentials (2 minutes)

```bash
aws configure
```

Enter when asked:
```
AWS Access Key ID     : [paste from supervisor]
AWS Secret Access Key : [paste from supervisor]
Default region name   : ap-southeast-1
Default output format : json
```

Test it works:
```bash
aws sts get-caller-identity
```
You should see your Account ID.

---

### STEP 3 — Create GitHub Repository (5 minutes)

1. Go to https://github.com/new
2. Repository name: AICGQAF-v1
3. Set to PRIVATE
4. Click Create repository

On your computer:
```bash
mkdir AICGQAF
cd AICGQAF
git init
git remote add origin https://github.com/YOURUSERNAME/AICGQAF-v1.git
```

Copy ALL files from the AICGQAF_Production ZIP into this folder.

---

### STEP 4 — Set Up AWS Infrastructure (10 minutes)

```bash
cd aws
bash 01_setup_aws.sh
```

This creates:
- S3 bucket for reports
- DynamoDB table for metrics
- SQS queue for Layer 3 tasks
- SNS topic for notifications
- IAM role for Lambda

After it finishes, it shows you values to copy.

---

### STEP 5 — Deploy Lambda Functions (5 minutes)

```bash
bash 02_deploy_lambdas.sh
```

This deploys three Lambda functions:
- aicgqaf-intake   (receives webhook)
- aicgqaf-gate1    (evaluates Gate 1)
- aicgqaf-gate2    (runs Layer 2 + evaluates Gate 2)

---

### STEP 6 — Add GitHub Secrets (5 minutes)

Go to: GitHub repo → Settings → Secrets and variables → Actions

Click "New repository secret" and add each one:

| Secret Name          | Value                        |
|----------------------|------------------------------|
| AWS_ACCESS_KEY_ID    | Your AWS access key          |
| AWS_SECRET_ACCESS_KEY| Your AWS secret key          |
| AWS_REGION           | ap-southeast-1               |
| ANTHROPIC_API_KEY    | From console.anthropic.com   |
| S3_BUCKET            | From aws_values.env          |
| DYNAMODB_TABLE       | aicgqaf-reviews              |
| SQS_QUEUE_URL        | From aws_values.env          |
| SNS_TOPIC_ARN        | From aws_values.env          |

---

### STEP 7 — Set Up Workflow File (2 minutes)

```bash
mkdir -p .github/workflows
cp github/aicgqaf.yml .github/workflows/aicgqaf.yml
```

---

### STEP 8 — Push to GitHub (2 minutes)

```bash
git add .
git commit -m "feat: AICGQAF v1.0 initial setup"
git push origin main
```

---

### STEP 9 — Test the Pipeline (15 minutes)

#### Test 1: SQL Injection (should FAIL at Layer 1)
```bash
git checkout -b test/sql-injection
mkdir -p api
cp test_prs/test_sqli_vulnerable.py api/search.py
git add .
git commit -m "feat: add user search endpoint"
git push origin test/sql-injection
```
Go to GitHub → Pull Requests → New Pull Request
Select: base=main, compare=test/sql-injection
Click Create pull request.

**Expected result:**
- GitHub Actions starts automatically
- Layer 1 detects CWE-89
- Pipeline FAILS
- PR comment posted: "AICGQAF — Rejected (Layer 1)"

#### Test 2: Hard-coded Credentials (should FAIL at Layer 1)
```bash
git checkout main
git checkout -b test/credentials
cp test_prs/test_creds_vulnerable.py config/aws_config.py
git add . && git commit -m "feat: add AWS config"
git push origin test/credentials
```
Open PR → watch pipeline FAIL with CWE-798.

#### Test 3: IDOR (full pipeline — should reach Layer 3)
```bash
git checkout main
git checkout -b test/idor-endpoint
mkdir -p api
cp test_prs/test_idor_vulnerable.py api/user_profile.py
git add . && git commit -m "feat: add user profile endpoint"
git push origin test/idor-endpoint
```
Open PR → watch pipeline:
1. Layer 1 ESCALATE
2. Layer 2 detects CWE-639
3. Layer 3 human review task created

#### Test 4: Clean Code (should APPROVE)
```bash
git checkout main
git checkout -b test/clean-endpoint
mkdir -p api
cp test_prs/test_clean_code.py api/products.py
git add . && git commit -m "feat: add product search endpoint"
git push origin test/clean-endpoint
```
Open PR → watch pipeline APPROVE automatically.

---

### STEP 10 — View Results (for Stage 5 Evaluation)

**GitHub Actions logs:**
Go to: GitHub repo → Actions → Select a workflow run

**S3 reports:**
```bash
aws s3 ls s3://YOUR_BUCKET/reviews/ --recursive
aws s3 cp s3://YOUR_BUCKET/reviews/REVIEW_ID/layer1_report.json .
```

**DynamoDB metrics:**
```bash
aws dynamodb scan --table-name aicgqaf-reviews --region ap-southeast-1
```

**Download all metrics as JSON:**
```bash
aws dynamodb scan \
  --table-name aicgqaf-reviews \
  --region ap-southeast-1 \
  --output json > aicgqaf_metrics.json
```

---

## EXPECTED PIPELINE RESULTS

| Test | Layer 1 | Layer 2 | Final | Path |
|------|---------|---------|-------|------|
| SQL Injection | FAIL (CWE-89) | Not reached | REJECTED | 2 |
| Hard-coded Creds | FAIL (CWE-798) | Not reached | REJECTED | 2 |
| IDOR Endpoint | ESCALATE | ESCALATE (CWE-639) | HUMAN REVIEW | 5 |
| Clean Code | PASS | APPROVE | APPROVED | 1/3 |

---

## COST SUMMARY

| Resource | Cost |
|----------|------|
| GitHub + Actions + CodeQL | FREE |
| Anthropic Claude API (~10 reviews) | ~$0.20 |
| AWS Lambda (100 invocations) | ~$0.00 |
| Amazon S3 (1 GB) | ~$0.02 |
| Amazon DynamoDB | ~$0.01 |
| **TOTAL for research** | **~$0.23** |

---

## TROUBLESHOOTING

**Problem: aws configure does not work**
Solution: Re-download AWS CLI from https://aws.amazon.com/cli/

**Problem: GitHub Actions shows "No such file"**
Solution: Check that scripts/ folder is committed to git

**Problem: Layer 2 shows "API key error"**
Solution: Check ANTHROPIC_API_KEY secret in GitHub Settings

**Problem: Lambda deploy fails**
Solution: Wait 30 seconds after running 01_setup_aws.sh then retry

**Problem: DynamoDB error**
Solution: Check AWS_REGION = ap-southeast-1 in GitHub Secrets
