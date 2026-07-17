"""
AICGQAF v1.0 - Quality Gate 1 Lambda
Koji Dan Seya | TP090490 | CT095-6-M

Reads Layer 1 JSON report from S3, applies Gate 1
threshold logic, updates DynamoDB, and either:
  - FAIL      → sends SNS rejection notification
  - PASS      → updates status to approved
  - ESCALATE  → invokes Gate 2 Lambda
"""
import json
import os
import boto3
from datetime import datetime, timezone

S3_BUCKET      = os.environ["S3_BUCKET"]
DYNAMODB_TABLE = os.environ["DYNAMODB_TABLE"]
SNS_TOPIC_ARN  = os.environ["SNS_TOPIC_ARN"]
AWS_REGION     = os.environ.get("AWS_REGION_NAME", "ap-southeast-1")

s3       = boto3.client("s3",      region_name=AWS_REGION)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
sns      = boto3.client("sns",     region_name=AWS_REGION)
lam      = boto3.client("lambda",  region_name=AWS_REGION)

# ── THRESHOLDS (from aicgqaf-config.yml Section 2.3) ─────────
FAIL_CWES   = {"CWE-79","CWE-89","CWE-798","CWE-22","CWE-78","CWE-94"}
THRESHOLDS  = {
    "critical_max":    0,
    "high_max":        0,
    "medium_min":      1,
    "smell_fail":     30.0,
    "smell_escalate": 10.0,
    "maintain_fail":  50,
    "maintain_esc":   70,
    "debt_fail":       5.0,
    "debt_esc":        2.0,
    "complexity_fail":15.0,
    "complexity_esc": 10.0,
}

def lambda_handler(event, context):
    review_id = event.get("review_id", "")
    print(f"[Gate1] Evaluating review: {review_id}")

    # Load Layer 1 report from S3
    try:
        obj = s3.get_object(Bucket=S3_BUCKET, Key=f"reviews/{review_id}/layer1_report.json")
        l1  = json.loads(obj["Body"].read())
    except Exception as e:
        print(f"[Gate1] ERROR loading L1 report: {e}")
        return {"decision": "ESCALATE", "reason": f"Layer 1 report unavailable: {e}"}

    decision, reason = evaluate_gate1(l1)

    # Update DynamoDB
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.update_item(
        Key={"review_id": review_id},
        UpdateExpression="SET #s=:s, gate1_decision=:d, gate1_reason=:r, updated_at=:t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": f"GATE1_{decision}",
            ":d": decision,
            ":r": reason,
            ":t": datetime.now(timezone.utc).isoformat()
        }
    )

    if decision == "FAIL":
        _notify(review_id, l1.get("pr_number", 0), reason, "REJECTED_L1")
        return {"decision": "FAIL", "reason": reason, "review_id": review_id}

    if decision == "PASS":
        _notify(review_id, l1.get("pr_number", 0), "All Layer 1 checks passed.", "APPROVED_L1")
        return {"decision": "PASS", "reason": reason, "review_id": review_id}

    # ESCALATE → invoke Gate 2
    print(f"[Gate1] Escalating to Gate 2: {reason}")
    lam.invoke(
        FunctionName="aicgqaf-gate2",
        InvocationType="Event",
        Payload=json.dumps({"review_id": review_id, "l1_report": l1})
    )
    return {"decision": "ESCALATE", "reason": reason, "review_id": review_id}


def evaluate_gate1(l1):
    """
    Applies Gate 1 thresholds in priority order.
    Returns (decision, reason).
    """
    cwes = {c.get("cwe_id","") for c in l1.get("cwe_violations",[])}

    # ── FAIL conditions ────────────────────────────────────────
    hit = cwes & FAIL_CWES
    if hit:
        return "FAIL", f"FAIL: Auto-reject CWE detected: {', '.join(sorted(hit))}"

    if l1.get("issues_critical",0) > THRESHOLDS["critical_max"]:
        return "FAIL", f"FAIL: {l1['issues_critical']} CRITICAL vulnerability(ies)"

    if l1.get("issues_high",0) > THRESHOLDS["high_max"]:
        return "FAIL", f"FAIL: {l1['issues_high']} HIGH vulnerability(ies)"

    smell = l1.get("code_smell_percent", 0)
    if smell > THRESHOLDS["smell_fail"]:
        return "FAIL", f"FAIL: Code smell {smell}% > {THRESHOLDS['smell_fail']}%"

    maintain = l1.get("maintainability_index", 100)
    if maintain < THRESHOLDS["maintain_fail"]:
        return "FAIL", f"FAIL: Maintainability {maintain} < {THRESHOLDS['maintain_fail']}"

    debt = l1.get("technical_debt_hours", 0)
    if debt > THRESHOLDS["debt_fail"]:
        return "FAIL", f"FAIL: Technical debt {debt}h > {THRESHOLDS['debt_fail']}h"

    # ── ESCALATE conditions ────────────────────────────────────
    reasons = []
    if l1.get("issues_medium",0) >= THRESHOLDS["medium_min"]:
        reasons.append(f"{l1['issues_medium']} MEDIUM issues")
    if smell >= THRESHOLDS["smell_escalate"]:
        reasons.append(f"Code smell {smell}% >= {THRESHOLDS['smell_escalate']}%")
    if maintain <= THRESHOLDS["maintain_esc"]:
        reasons.append(f"Maintainability {maintain} <= {THRESHOLDS['maintain_esc']}")
    if debt >= THRESHOLDS["debt_esc"]:
        reasons.append(f"Technical debt {debt}h >= {THRESHOLDS['debt_esc']}h")
    complexity = l1.get("cyclomatic_complexity", 0)
    if complexity > THRESHOLDS["complexity_esc"]:
        reasons.append(f"Complexity {complexity} > {THRESHOLDS['complexity_esc']}")

    if reasons:
        return "ESCALATE", "ESCALATE: " + "; ".join(reasons)

    return "PASS", "All Quality Gate 1 thresholds met."


def _notify(review_id, pr_number, message, event_type):
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"AICGQAF - {event_type} - PR #{pr_number}",
            Message=f"Review: {review_id}\nPR: #{pr_number}\n\n{message}",
            MessageAttributes={
                "event_type": {"DataType":"String","StringValue":event_type}
            }
        )
    except Exception as e:
        print(f"[Gate1] SNS error: {e}")
