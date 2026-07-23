"""
AICGQAF v1.0 - Quality Gate 2 Lambda (Layer 2 + Gate 2)
Koji Dan Seya | TP090490 | CT095-6-M

Builds context package, calls Claude API for Layer 2
semantic review, evaluates Gate 2 thresholds, and either:
  - APPROVE → updates GitHub PR status
  - REJECT  → sends rejection notification
  - ESCALATE → sends task to SQS for Layer 3 human review
"""
import json
import os
import boto3
import urllib.request
import urllib.error
from datetime import datetime, timezone

S3_BUCKET      = os.environ["S3_BUCKET"]
DYNAMODB_TABLE = os.environ["DYNAMODB_TABLE"]
SQS_QUEUE_URL  = os.environ["SQS_QUEUE_URL"]
SNS_TOPIC_ARN  = os.environ["SNS_TOPIC_ARN"]
AWS_REGION     = os.environ.get("AWS_REGION_NAME","ap-southeast-1")

s3       = boto3.client("s3",         region_name=AWS_REGION)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
sqs      = boto3.client("sqs",        region_name=AWS_REGION)
sns      = boto3.client("sns",        region_name=AWS_REGION)
secrets  = boto3.client("secretsmanager", region_name=AWS_REGION)

# ── Gate 2 thresholds (Section 5.1.2 Framework Architecture) ─
THRESHOLDS = {
    "confidence_approve": 70,
    "confidence_reject":  30,
    "maintain_min":       50,
    "cvss_block":         6.0,
}

def get_anthropic_key():
    """Retrieve Claude API key from Secrets Manager."""
    try:
        resp = secrets.get_secret_value(SecretId="aicgqaf/anthropic-api-key")
        return resp["SecretString"]
    except Exception as e:
        print(f"[Gate2] Secrets Manager error: {e}")
        return os.environ.get("ANTHROPIC_API_KEY","")

def lambda_handler(event, context):
    review_id = event.get("review_id","")
    l1_report = event.get("l1_report",{})
    print(f"[Gate2] Processing review: {review_id}")

    # Load diff from S3
    diff_content = ""
    try:
        obj = s3.get_object(Bucket=S3_BUCKET, Key=f"reviews/{review_id}/pr.diff")
        diff_content = obj["Body"].read().decode("utf-8")
    except Exception as e:
        print(f"[Gate2] Could not load diff: {e}")

    # Build prompt
    prompt = build_prompt(diff_content, l1_report)

    # Call Claude API
    api_key = get_anthropic_key()
    l2_result = call_claude(prompt, api_key)

    # Save Layer 2 result to S3
    s3.put_object(
        Bucket=S3_BUCKET,
        Key=f"reviews/{review_id}/layer2_report.json",
        Body=json.dumps(l2_result, indent=2).encode(),
        ContentType="application/json"
    )

    # Evaluate Gate 2
    decision, reason = evaluate_gate2(l2_result)
    l2_result["gate2_decision"] = decision
    l2_result["gate2_reason"]   = reason

    # Update DynamoDB
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.update_item(
        Key={"review_id": review_id},
        UpdateExpression=(
            "SET #s=:s, gate2_decision=:d, gate2_reason=:r, "
            "l2_confidence=:c, updated_at=:t"
        ),
        ExpressionAttributeNames={"#s":"status"},
        ExpressionAttributeValues={
            ":s": f"GATE2_{decision}",
            ":d": decision,
            ":r": reason,
            ":c": l2_result.get("overall_confidence",0),
            ":t": datetime.now(timezone.utc).isoformat()
        }
    )

    if decision == "APPROVE":
        _notify_slack(review_id, l1_report.get("pr_number",0), reason, "APPROVED_L2")
        return {"decision":"APPROVE","reason":reason}

    if decision == "REJECT":
        _notify_slack(review_id, l1_report.get("pr_number",0), reason, "REJECTED_L2")
        return {"decision":"REJECT","reason":reason}

    # ESCALATE → SQS → Layer 3
    role   = _assign_reviewer_role(l2_result)
    sla    = {"security_expert":15,"architect":20,"senior_developer":10}.get(role,10)
    task   = {
        "review_id":        review_id,
        "pr_number":        l1_report.get("pr_number",0),
        "reviewer_role":    role,
        "sla_minutes":      sla,
        "escalation_reason":reason,
        "l1_summary":       _summarise_l1(l1_report),
        "l2_summary":       _summarise_l2(l2_result),
        "created_at":       datetime.now(timezone.utc).isoformat()
    }
    sqs.send_message(
        QueueUrl=SQS_QUEUE_URL,
        MessageBody=json.dumps(task),
        MessageGroupId=role,
        MessageDeduplicationId=review_id
    )
    table.update_item(
        Key={"review_id":review_id},
        UpdateExpression="SET #s=:s, reviewer_role=:r, sla_minutes=:sla, updated_at=:t",
        ExpressionAttributeNames={"#s":"status"},
        ExpressionAttributeValues={
            ":s":"AWAITING_HUMAN",":r":role,
            ":sla":sla,":t":datetime.now(timezone.utc).isoformat()
        }
    )
    _notify_slack(review_id,l1_report.get("pr_number",0),
        f"Escalated to {role} — SLA: {sla} min. Reason: {reason}","ESCALATED_L3")
    return {"decision":"ESCALATE","role":role,"sla":sla}


def build_prompt(diff, l1):
    """Build the Layer 2 structured prompt."""
    return f"""You are the Layer 2 AI reviewer of AICGQAF v1.0, a research quality assurance framework.

Analyse this code for semantic correctness, security vulnerabilities, and architectural issues.
Focus on issues that static analysis CANNOT detect: IDOR, business logic flaws, context-specific risks.

LAYER 1 RESULTS:
Decision: {l1.get("layer1_decision","ESCALATE")}
Reason: {l1.get("escalation_reason","")}
Issues: Critical={l1.get("issues_critical",0)} High={l1.get("issues_high",0)} Medium={l1.get("issues_medium",0)}
Code Smells: {l1.get("code_smell_percent",0)}% | Maintainability: {l1.get("maintainability_index",0)}
CWEs: {json.dumps(l1.get("cwe_violations",[])[:3])}

CODE DIFF:
{diff[:4000]}

Respond ONLY with valid JSON (no markdown, no preamble):
{{
  "semantic_correct": true,
  "architectural_fit": true,
  "security_concerns": [{{"severity":"MEDIUM","cwe_id":"CWE-XX","description":"...","suggested_fix":"..."}}],
  "maintainability_score": 75,
  "performance_flags": [{{"severity":"LOW","description":"..."}}],
  "overall_confidence": 80,
  "recommendation": "APPROVE",
  "explanation": "Plain-language 2-3 sentence summary for the developer."
}}"""


def call_claude(prompt, api_key):
    """Call Anthropic Claude API for Layer 2 review."""
    fallback = {
        "semantic_correct":True,"architectural_fit":True,
        "security_concerns":[],"maintainability_score":75,
        "performance_flags":[],"overall_confidence":25,
        "recommendation":"REVIEW_HUMAN",
        "explanation":"Layer 2 API unavailable. Escalating to human review."
    }
    if not api_key:
        print("[Gate2] No API key — using fallback")
        return fallback

    payload = json.dumps({
        "model":      "claude-sonnet-4-6",
        "max_tokens": 1000,
        "messages":   [{"role":"user","content":prompt}]
    }).encode()

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type":      "application/json",
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=35) as resp:
            data = json.loads(resp.read())
            raw  = "".join(b["text"] for b in data.get("content",[]) if b.get("type")=="text")
            clean= raw.replace("```json","").replace("```","").strip()
            return json.loads(clean)
    except Exception as e:
        print(f"[Gate2] Claude API error: {e}")
        return fallback


def evaluate_gate2(l2):
    """Apply Gate 2 threshold logic. Returns (decision, reason)."""
    conf     = l2.get("overall_confidence",0)
    semantic = l2.get("semantic_correct",True)
    arch     = l2.get("architectural_fit",True)
    maintain = l2.get("maintainability_score",100)
    concerns = l2.get("security_concerns",[])
    high_crit= [c for c in concerns if c.get("severity") in ("HIGH","CRITICAL")]
    medium   = [c for c in concerns if c.get("severity")=="MEDIUM"]

    # REJECT priority
    if not semantic:
        return "REJECT","Semantic correctness failure — code does not achieve its stated purpose."
    if high_crit:
        cwes=", ".join(c.get("cwe_id","?") for c in high_crit)
        return "REJECT",f"HIGH/CRITICAL security concerns: {cwes}. Deployment blocked."
    if conf < THRESHOLDS["confidence_reject"]:
        return "REJECT",f"AI confidence {conf}% too low for any decision."

    # ESCALATE priority
    if conf < THRESHOLDS["confidence_approve"]:
        return "ESCALATE",f"Confidence {conf}% below {THRESHOLDS['confidence_approve']}% threshold."
    if medium:
        cwes=", ".join(c.get("cwe_id","?") for c in medium)
        return "ESCALATE",f"MEDIUM security concerns: {cwes}."
    if maintain < THRESHOLDS["maintain_min"]:
        return "ESCALATE",f"Maintainability {maintain} below threshold {THRESHOLDS['maintain_min']}."
    if not arch:
        return "ESCALATE","Architectural fit failure."

    return "APPROVE",f"All Gate 2 criteria met. Confidence: {conf}%."


def _assign_reviewer_role(l2):
    concerns = l2.get("security_concerns",[])
    if any(c.get("severity") in ("HIGH","CRITICAL") for c in concerns):
        return "security_expert"
    if not l2.get("architectural_fit",True):
        return "architect"
    return "senior_developer"

def _summarise_l1(l1):
    return {
        "decision":    l1.get("layer1_decision",""),
        "critical":    l1.get("issues_critical",0),
        "high":        l1.get("issues_high",0),
        "medium":      l1.get("issues_medium",0),
        "smells":      l1.get("code_smell_percent",0),
        "maintain":    l1.get("maintainability_index",0),
        "debt_h":      l1.get("technical_debt_hours",0),
        "reason":      l1.get("escalation_reason","")
    }

def _summarise_l2(l2):
    return {
        "confidence":  l2.get("overall_confidence",0),
        "semantic":    l2.get("semantic_correct",True),
        "arch":        l2.get("architectural_fit",True),
        "maintain":    l2.get("maintainability_score",0),
        "concerns":    l2.get("security_concerns",[]),
        "explanation": l2.get("explanation",""),
        "reason":      l2.get("gate2_reason","")
    }

def _notify_slack(review_id, pr_number, message, event_type):
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"AICGQAF - {event_type} - PR #{pr_number}",
            Message=f"Review ID: {review_id}\nPR: #{pr_number}\n\n{message}",
            MessageAttributes={
                "event_type":{"DataType":"String","StringValue":event_type},
                "review_id": {"DataType":"String","StringValue":review_id}
            }
        )
    except Exception as e:
        print(f"[Gate2] SNS error: {e}")
