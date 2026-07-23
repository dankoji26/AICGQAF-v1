# AICGQAF v1.0 — AI Code Generation Quality Assurance Framework

**Koji Dan Seya | TP090490 | APUMF2508SE(PR)**
**Module: CT095-6-M | Supervisor: Amad Arshad**
**Asia Pacific University of Technology & Innovation**

## What This Is

AICGQAF v1.0 is the research artefact for the MSc Software Engineering
final project "AI Code Generation Quality Control". It implements a
three-tier quality assurance pipeline using Design Science Research (DSR).

## Three-Tier Pipeline

```
Pull Request → GitHub Actions
    ↓
Layer 1: Static Analysis (CodeQL + Bandit)
    ↓
Quality Gate 1: FAIL / ESCALATE / PASS
    ↓ (if ESCALATE)
Layer 2: Claude AI Semantic Review
    ↓
Quality Gate 2: REJECT / ESCALATE / APPROVE
    ↓ (if ESCALATE)
Layer 3: Human Review Dashboard
    ↓
Final Decision → GitHub PR Comment
```

## Setup Instructions

### Prerequisites
- GitHub account
- AWS account (IAM user with permissions)
- Anthropic API key (https://console.anthropic.com)
- Python 3.11+
- AWS CLI

### Step 1: AWS Infrastructure
```bash
cd aws
bash 01_setup_aws.sh
```

### Step 2: Deploy Lambda Functions
```bash
bash 02_deploy_lambdas.sh
```

### Step 3: Add GitHub Secrets
Go to: Settings → Secrets → Actions → New repository secret

Required secrets:
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- AWS_REGION = ap-southeast-1
- ANTHROPIC_API_KEY
- S3_BUCKET
- DYNAMODB_TABLE = aicgqaf-reviews
- SQS_QUEUE_URL
- SNS_TOPIC_ARN

### Step 4: Copy Workflow File
```bash
mkdir -p .github/workflows
cp github/aicgqaf.yml .github/workflows/aicgqaf.yml
```

### Step 5: Test the Pipeline
```bash
git checkout -b test/sql-injection
cp test_prs/test_sqli_vulnerable.py api/search.py
git add . && git commit -m "test: add search endpoint"
git push origin test/sql-injection
```
Then open a Pull Request on GitHub and watch the pipeline run.

## Expected Results Per Test File

| Test File | Expected Layer 1 | Expected Layer 2 | Expected Path |
|-----------|-----------------|-----------------|---------------|
| test_sqli_vulnerable.py | FAIL (CWE-89) | Not reached | Path 2 |
| test_creds_vulnerable.py | FAIL (CWE-798) | Not reached | Path 2 |
| test_idor_vulnerable.py | ESCALATE | ESCALATE (CWE-639) | Path 5 |
| test_clean_code.py | PASS/ESCALATE | APPROVE | Path 1/3 |

## Cost

| Resource | Monthly Cost |
|----------|-------------|
| GitHub + GitHub Actions + CodeQL | Free |
| Anthropic Claude API (500 reviews) | ~$10.00 |
| AWS Lambda (100,000 invocations) | ~$0.20 |
| Amazon S3 (50 GB) | ~$1.15 |
| Amazon DynamoDB (on-demand) | ~$2.50 |
| **Total** | **~$13.85/month** |

## Empirical Basis

- CodeRabbit (2025): AI code has 1.7x more defects per PR
- Veracode (2025): 45% of AI exercises yield critical vulnerabilities
- Sabra et al. (2025): 90-93% of AI issues are code smells
- Cihan et al. (2025): Context is critical for AI review accuracy
- Schreiber & Tippe (2025): 46.32% of AI code triggers CodeQL alerts
