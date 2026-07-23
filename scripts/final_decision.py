"""
AICGQAF v1.0 — Final Decision Orchestrator & Quality Gate 3
============================================================
Koji Dan Seya | TP090490 | CT095-6-M
Asia Pacific University of Technology & Innovation

Reads the combined Layer 1 + Layer 2 outputs, determines the final
pipeline path, and either approves the merge, triggers human review
(Layer 3 via SQS), or rejects the PR.

Also handles the Layer 3 human decision webhook callback.

Usage (pipeline):
    python final_decision.py \
        --review-id <uuid> \
        --layer1-report /tmp/layer1_report.json \
        --layer2-report /tmp/layer2_report.json \
        --pr-number 42 \
        --repo-url https://github.com/org/repo \
        --github-token $GITHUB_TOKEN

Usage (Layer 3 callback — called by the dashboard):
    python final_decision.py \
        --mode human-decision \
        --review-id <uuid> \
        --human-decision APPROVE \
        --reviewer-id security_expert_001 \
        --comment "Verified no SQL injection vectors present."
"""

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone

import boto3
import requests

# ─── Configuration ────────────────────────────────────────────────────────────
S3_BUCKET         = os.getenv("S3_BUCKET",        "aicgqaf-artifacts")
DYNAMODB_TABLE    = os.getenv("DYNAMODB_TABLE",    "aicgqaf-reviews")
SQS_QUEUE_URL     = os.getenv("SQS_QUEUE_URL",     "")
SNS_TOPIC_ARN     = os.getenv("SNS_TOPIC_ARN",     "")
AWS_REGION        = os.getenv("AWS_REGION",        "ap-southeast-1")
GITHUB_API_URL    = "https://api.github.com"
DASHBOARD_BASE_URL= os.getenv("DASHBOARD_URL",     "https://aicgqaf-dashboard.example.com")

# ─── Path definitions (Section 5.2 of Framework Architecture) ─────────────────
#   Path 1: L1=PASS                     → AUTO-MERGE
#   Path 2: L1=FAIL                     → REJECT
#   Path 3: L1=ESCALATE, L2=APPROVE     → AUTO-MERGE
#   Path 4: L1=ESCALATE, L2=REJECT      → REJECT
#   Path 5: L1=ESCALATE, L2=ESCALATE, L3=APPROVE        → MERGE
#   Path 6: L1=ESCALATE, L2=ESCALATE, L3=REQUEST_CHANGES→ RE-ENTER
#   Path 7: L1=ESCALATE, L2=ESCALATE, L3=REJECT         → REJECT


# ═══════════════════════════════════════════════════════════════════════════════
# 1. PIPELINE DECISION LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

def determine_pipeline_path(l1_decision: str, l2_decision: str | None) -> str:
    """
    Maps Layer 1 and Layer 2 decisions to a named pipeline path.
    Layer 2 decision is None when Layer 1 passed or failed without escalation.
    """
    if l1_decision == "PASS":
        return "PATH_1_AUTO_MERGE"
    if l1_decision == "FAIL":
        return "PATH_2_REJECT_L1"
    # l1_decision == "ESCALATE"
    if l2_decision == "APPROVE":
        return "PATH_3_AUTO_MERGE"
    if l2_decision == "REJECT":
        return "PATH_4_REJECT_L2"
    if l2_decision in ("ESCALATE", None):
        return "PATH_5_6_7_HUMAN"
    return "PATH_UNKNOWN"


def execute_pipeline_path(path: str, context: dict) -> dict:
    """
    Executes the action for the determined pipeline path.
    Returns a result dict with the final status and action taken.
    """
    review_id  = context["review_id"]
    pr_number  = context["pr_number"]
    repo_url   = context["repo_url"]
    github_token = context.get("github_token", "")

    handlers = {
        "PATH_1_AUTO_MERGE": _handle_auto_merge,
        "PATH_2_REJECT_L1":  _handle_reject,
        "PATH_3_AUTO_MERGE": _handle_auto_merge,
        "PATH_4_REJECT_L2":  _handle_reject,
        "PATH_5_6_7_HUMAN":  _handle_escalate_to_human,
        "PATH_UNKNOWN":      _handle_unknown,
    }

    handler = handlers.get(path, _handle_unknown)
    result  = handler(path, context)
    _record_final_decision(review_id, path, result)
    return result


def _handle_auto_merge(path: str, ctx: dict) -> dict:
    """Approves the PR via the GitHub API and notifies the developer."""
    print(f"[Decision] {path} → AUTO-MERGE")

    l1 = ctx.get("layer1_report", {})
    l2 = ctx.get("layer2_report", {})

    # Determine which layer approved it
    approving_layer = 1 if path == "PATH_1_AUTO_MERGE" else 2
    confidence = l2.get("overall_confidence", 95) if approving_layer == 2 else 95

    comment_body = _build_approval_comment(path, l1, l2, confidence)
    _post_github_pr_comment(ctx["pr_number"], ctx["repo_url"], ctx.get("github_token",""), comment_body)
    _approve_github_pr(ctx["pr_number"], ctx["repo_url"], ctx.get("github_token",""))
    _send_notification("APPROVED", ctx, comment_body)

    return {
        "final_status":       "APPROVED",
        "merge_allowed":      True,
        "approving_layer":    approving_layer,
        "notification_sent":  True,
        "path":               path,
    }


def _handle_reject(path: str, ctx: dict) -> dict:
    """Rejects the PR with detailed feedback via a GitHub comment."""
    print(f"[Decision] {path} → REJECT")

    l1 = ctx.get("layer1_report", {})
    l2 = ctx.get("layer2_report", {})

    rejecting_layer = 1 if path == "PATH_2_REJECT_L1" else 2
    reason = (
        l1.get("escalation_reason", "Quality gate failure")
        if rejecting_layer == 1
        else l2.get("gate2_reason", "Semantic or security review failure")
    )

    comment_body = _build_rejection_comment(path, l1, l2, reason, rejecting_layer)
    _post_github_pr_comment(ctx["pr_number"], ctx["repo_url"], ctx.get("github_token",""), comment_body)
    _request_github_pr_changes(ctx["pr_number"], ctx["repo_url"], ctx.get("github_token",""), comment_body)
    _send_notification("REJECTED", ctx, reason)

    return {
        "final_status":      "REJECTED",
        "merge_allowed":     False,
        "rejecting_layer":   rejecting_layer,
        "rejection_reason":  reason,
        "notification_sent": True,
        "path":              path,
    }


def _handle_escalate_to_human(path: str, ctx: dict) -> dict:
    """Creates a Layer 3 human review task in the SQS queue."""
    print(f"[Decision] {path} → ESCALATE TO HUMAN REVIEW")

    l1 = ctx.get("layer1_report", {})
    l2 = ctx.get("layer2_report", {})

    # Determine reviewer role based on escalation context
    reviewer_role = _determine_reviewer_role(l1, l2)
    sla_minutes   = {"security_expert": 15, "architect": 20, "senior_developer": 10}.get(reviewer_role, 10)

    # Build the review task
    task = {
        "review_id":        ctx["review_id"],
        "pr_number":        ctx["pr_number"],
        "repo_url":         ctx["repo_url"],
        "reviewer_role":    reviewer_role,
        "sla_minutes":      sla_minutes,
        "sla_deadline":     _compute_sla_deadline(sla_minutes),
        "layer1_summary":   _summarise_l1(l1),
        "layer2_summary":   _summarise_l2(l2),
        "escalation_reason":l2.get("gate2_reason") or l1.get("escalation_reason", "Escalated for review"),
        "dashboard_url":    f"{DASHBOARD_BASE_URL}/review/{ctx['review_id']}",
        "created_at":       datetime.now(timezone.utc).isoformat(),
    }

    # Push to SQS FIFO queue
    task_id = _enqueue_review_task(task)

    # Notify reviewer
    notification_msg = (
        f"Human review required for PR #{ctx['pr_number']}.\n"
        f"Reviewer role: {reviewer_role.replace('_', ' ').title()}\n"
        f"SLA: {sla_minutes} minutes\n"
        f"Dashboard: {task['dashboard_url']}\n"
        f"Reason: {task['escalation_reason']}"
    )
    _send_notification(f"ESCALATED_TO_{reviewer_role.upper()}", ctx, notification_msg)

    # Post a PR comment so the developer knows their code is under review
    _post_github_pr_comment(
        ctx["pr_number"], ctx["repo_url"], ctx.get("github_token", ""),
        f"🔍 **AICGQAF — Human Review Required**\n\n"
        f"Your pull request has been escalated to a **{reviewer_role.replace('_', ' ').title()}** "
        f"for human review.\n\n"
        f"**Reason:** {task['escalation_reason']}\n\n"
        f"Expected response within **{sla_minutes} minutes**."
    )

    return {
        "final_status":      "AWAITING_HUMAN",
        "merge_allowed":     False,
        "reviewer_role":     reviewer_role,
        "sla_minutes":       sla_minutes,
        "task_id":           task_id,
        "notification_sent": True,
        "path":              path,
    }


def _handle_unknown(path: str, ctx: dict) -> dict:
    """Fallback handler for unexpected pipeline states — defaults to human review."""
    print(f"[Decision] WARNING: Unknown path '{path}' — defaulting to human escalation")
    return _handle_escalate_to_human("PATH_5_6_7_HUMAN", ctx)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. HUMAN DECISION CALLBACK (Layer 3)
# ═══════════════════════════════════════════════════════════════════════════════

def process_human_decision(
    review_id: str,
    decision: str,
    reviewer_id: str,
    comment: str,
    suggested_fix: str = "",
) -> dict:
    """
    Processes the human reviewer's decision from the Layer 3 dashboard.
    Called via the /api/v1/reviews/{review_id}/layer3/decision endpoint.

    decision: "APPROVE" | "REQUEST_CHANGES" | "REJECT"
    """
    print(f"\n[Layer 3] Human decision received: {decision} by {reviewer_id}")

    # Load review context from DynamoDB
    ctx = _load_review_context(review_id)
    if not ctx:
        return {"error": f"Review {review_id} not found"}

    pr_number    = ctx.get("pr_number", 0)
    repo_url     = ctx.get("repo_url", "")
    github_token = ctx.get("github_token", "")

    if decision == "APPROVE":
        result = _execute_human_approve(review_id, pr_number, repo_url, github_token, reviewer_id, comment)

    elif decision == "REQUEST_CHANGES":
        result = _execute_human_request_changes(review_id, pr_number, repo_url, github_token, reviewer_id, comment, suggested_fix)

    elif decision == "REJECT":
        result = _execute_human_reject(review_id, pr_number, repo_url, github_token, reviewer_id, comment)

    else:
        return {"error": f"Invalid decision value: {decision}"}

    # Record in DynamoDB
    _record_human_decision(review_id, decision, reviewer_id, comment, suggested_fix)

    # Check for override (human contradicts Layer 2 recommendation)
    l2_report = ctx.get("layer2_report", {})
    l2_rec = l2_report.get("recommendation", "")
    if (l2_rec == "REJECT" and decision == "APPROVE") or (l2_rec == "APPROVE" and decision == "REJECT"):
        _flag_override(review_id, l2_rec, decision, reviewer_id, comment)

    return result


def _execute_human_approve(review_id, pr_number, repo_url, token, reviewer_id, comment):
    comment_body = (
        f"✅ **AICGQAF — Approved by Human Reviewer**\n\n"
        f"**Reviewer:** {reviewer_id}\n"
        f"**Decision:** APPROVED\n\n"
        f"**Comments:** {comment}"
    )
    _post_github_pr_comment(pr_number, repo_url, token, comment_body)
    _approve_github_pr(pr_number, repo_url, token)
    print(f"[Layer 3] PR #{pr_number} approved by {reviewer_id}")
    return {"final_status": "APPROVED", "merge_allowed": True, "reviewer_id": reviewer_id}


def _execute_human_request_changes(review_id, pr_number, repo_url, token, reviewer_id, comment, suggested_fix):
    fix_section = f"\n\n**Suggested Fix:**\n```\n{suggested_fix}\n```" if suggested_fix else ""
    comment_body = (
        f"🔄 **AICGQAF — Changes Requested**\n\n"
        f"**Reviewer:** {reviewer_id}\n"
        f"**Decision:** REQUEST CHANGES\n\n"
        f"**Feedback:** {comment}{fix_section}\n\n"
        f"Please update your pull request and resubmit. "
        f"The updated PR will re-enter the AICGQAF pipeline from Layer 1."
    )
    _request_github_pr_changes(pr_number, repo_url, token, comment_body)
    print(f"[Layer 3] Changes requested on PR #{pr_number} by {reviewer_id}")
    return {"final_status": "CHANGES_REQUESTED", "merge_allowed": False, "reviewer_id": reviewer_id}


def _execute_human_reject(review_id, pr_number, repo_url, token, reviewer_id, comment):
    comment_body = (
        f"❌ **AICGQAF — Rejected by Human Reviewer**\n\n"
        f"**Reviewer:** {reviewer_id}\n"
        f"**Decision:** REJECTED\n\n"
        f"**Reason:** {comment}\n\n"
        f"This pull request has been permanently rejected. "
        f"Please open a new pull request with a revised approach."
    )
    _post_github_pr_comment(pr_number, repo_url, token, comment_body)
    _close_github_pr(pr_number, repo_url, token)
    print(f"[Layer 3] PR #{pr_number} rejected by {reviewer_id}")
    return {"final_status": "REJECTED", "merge_allowed": False, "reviewer_id": reviewer_id}


# ═══════════════════════════════════════════════════════════════════════════════
# 3. HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _determine_reviewer_role(l1: dict, l2: dict) -> str:
    """Maps escalation context to the appropriate reviewer role."""
    security_cwes = {c.get("cwe_id","") for c in l2.get("security_concerns",[])}
    high_severity  = any(c.get("severity") in ("HIGH","CRITICAL") for c in l2.get("security_concerns",[]))
    arch_fail      = not l2.get("architectural_fit", True)

    # HIGH security concerns or auto-reject CWEs → security expert
    if high_severity or (security_cwes & {"CWE-79","CWE-89","CWE-798","CWE-22"}):
        return "security_expert"
    # Architecture mismatch → architecture reviewer
    if arch_fail:
        return "architect"
    # Default
    return "senior_developer"


def _compute_sla_deadline(sla_minutes: int) -> str:
    from datetime import timedelta
    deadline = datetime.now(timezone.utc) + timedelta(minutes=sla_minutes)
    return deadline.isoformat()


def _summarise_l1(l1: dict) -> dict:
    return {
        "decision":       l1.get("layer1_decision", "ESCALATE"),
        "critical":       l1.get("issues_critical", 0),
        "high":           l1.get("issues_high", 0),
        "medium":         l1.get("issues_medium", 0),
        "code_smells":    l1.get("code_smell_percent", 0),
        "maintainability":l1.get("maintainability_index", 0),
        "tech_debt_h":    l1.get("technical_debt_hours", 0),
        "reason":         l1.get("escalation_reason", ""),
    }


def _summarise_l2(l2: dict) -> dict:
    return {
        "decision":       l2.get("gate2_decision", "ESCALATE"),
        "confidence":     l2.get("overall_confidence", 0),
        "semantic":       l2.get("semantic_correct", True),
        "arch_fit":       l2.get("architectural_fit", True),
        "maintainability":l2.get("maintainability_score", 0),
        "concerns":       l2.get("security_concerns", []),
        "explanation":    l2.get("explanation", ""),
        "reason":         l2.get("gate2_reason", ""),
    }


def _enqueue_review_task(task: dict) -> str:
    """Sends the human review task to the SQS FIFO queue."""
    sqs = boto3.client("sqs", region_name=AWS_REGION)
    msg_group = task.get("reviewer_role", "senior_developer")
    response = sqs.send_message(
        QueueUrl=SQS_QUEUE_URL,
        MessageBody=json.dumps(task),
        MessageGroupId=msg_group,
        MessageDeduplicationId=task["review_id"],
        MessageAttributes={
            "reviewer_role": {"StringValue": task["reviewer_role"], "DataType": "String"},
            "sla_minutes":   {"StringValue": str(task["sla_minutes"]), "DataType": "Number"},
        },
    )
    return response.get("MessageId", "")


def _record_final_decision(review_id: str, path: str, result: dict) -> None:
    try:
        dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
        table = dynamodb.Table(DYNAMODB_TABLE)
        table.update_item(
            Key={"review_id": review_id},
            UpdateExpression="SET pipeline_path = :p, final_status = :s, final_result = :r, completed_at = :t",
            ExpressionAttributeValues={
                ":p": path,
                ":s": result.get("final_status", "UNKNOWN"),
                ":r": json.dumps(result),
                ":t": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception as e:
        print(f"[Decision] DynamoDB update failed: {e}")


def _record_human_decision(review_id, decision, reviewer_id, comment, suggested_fix):
    try:
        dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
        table = dynamodb.Table(DYNAMODB_TABLE)
        table.update_item(
            Key={"review_id": review_id},
            UpdateExpression=(
                "SET #status = :s, human_decision = :d, reviewer_id = :r, "
                "human_comment = :c, suggested_fix = :f, human_decided_at = :t"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":s": f"HUMAN_{decision}",
                ":d": decision,
                ":r": reviewer_id,
                ":c": comment,
                ":f": suggested_fix,
                ":t": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception as e:
        print(f"[Layer 3] DynamoDB human decision update failed: {e}")


def _flag_override(review_id, l2_recommendation, human_decision, reviewer_id, comment):
    """Flags override decisions for Layer 2 calibration feedback."""
    print(f"[Layer 3] Override detected: L2={l2_recommendation}, Human={human_decision}")
    try:
        dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
        table = dynamodb.Table(DYNAMODB_TABLE)
        table.update_item(
            Key={"review_id": review_id},
            UpdateExpression="SET is_override = :t, l2_recommendation = :l2",
            ExpressionAttributeValues={":t": True, ":l2": l2_recommendation},
        )
    except Exception as e:
        print(f"[Layer 3] Override flag failed: {e}")


def _load_review_context(review_id: str) -> dict | None:
    try:
        dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
        table = dynamodb.Table(DYNAMODB_TABLE)
        item = table.get_item(Key={"review_id": review_id}).get("Item")
        return item
    except Exception:
        return None


def _post_github_pr_comment(pr_number: int, repo_url: str, token: str, body: str) -> None:
    if not token or not repo_url:
        print(f"[GitHub] Skipping comment (no token/URL): {body[:80]}...")
        return
    repo_path = repo_url.replace("https://github.com/", "")
    url = f"{GITHUB_API_URL}/repos/{repo_path}/issues/{pr_number}/comments"
    try:
        requests.post(url, headers={"Authorization": f"Bearer {token}"}, json={"body": body}, timeout=10)
    except Exception as e:
        print(f"[GitHub] Comment failed: {e}")


def _approve_github_pr(pr_number, repo_url, token):
    if not token or not repo_url: return
    repo_path = repo_url.replace("https://github.com/", "")
    url = f"{GITHUB_API_URL}/repos/{repo_path}/pulls/{pr_number}/reviews"
    try:
        requests.post(url, headers={"Authorization": f"Bearer {token}"},
                      json={"event": "APPROVE", "body": "AICGQAF — Approved."}, timeout=10)
    except Exception as e:
        print(f"[GitHub] Approve failed: {e}")


def _request_github_pr_changes(pr_number, repo_url, token, body):
    if not token or not repo_url: return
    repo_path = repo_url.replace("https://github.com/", "")
    url = f"{GITHUB_API_URL}/repos/{repo_path}/pulls/{pr_number}/reviews"
    try:
        requests.post(url, headers={"Authorization": f"Bearer {token}"},
                      json={"event": "REQUEST_CHANGES", "body": body}, timeout=10)
    except Exception as e:
        print(f"[GitHub] Request changes failed: {e}")


def _close_github_pr(pr_number, repo_url, token):
    if not token or not repo_url: return
    repo_path = repo_url.replace("https://github.com/", "")
    url = f"{GITHUB_API_URL}/repos/{repo_path}/pulls/{pr_number}"
    try:
        requests.patch(url, headers={"Authorization": f"Bearer {token}"},
                       json={"state": "closed"}, timeout=10)
    except Exception as e:
        print(f"[GitHub] Close PR failed: {e}")


def _send_notification(event_type: str, ctx: dict, message: str) -> None:
    """Sends an SNS notification for monitoring and Slack integration."""
    if not SNS_TOPIC_ARN: return
    try:
        sns = boto3.client("sns", region_name=AWS_REGION)
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"AICGQAF — {event_type} — PR #{ctx.get('pr_number','')}",
            Message=message,
            MessageAttributes={
                "event_type": {"DataType": "String", "StringValue": event_type},
                "review_id":  {"DataType": "String", "StringValue": ctx.get("review_id", "")},
            },
        )
    except Exception as e:
        print(f"[Notification] SNS publish failed: {e}")


def _build_approval_comment(path, l1, l2, confidence):
    layer = 1 if "PATH_1" in path else 2
    return (
        f"✅ **AICGQAF v1.0 — Approved (Layer {layer})**\n\n"
        f"| Metric | Value |\n|---|---|\n"
        f"| Decision | ✅ APPROVED |\n"
        f"| Approving Layer | Layer {layer} |\n"
        f"| AI Confidence | {confidence}% |\n"
        f"| Code Smells | {l1.get('code_smell_percent',0)}% |\n"
        f"| Maintainability | {l1.get('maintainability_index',0)} |\n"
        f"| Technical Debt | {l1.get('technical_debt_hours',0)}h |\n\n"
        f"All quality gates passed. This pull request is approved for merge. 🚀"
    )


def _build_rejection_comment(path, l1, l2, reason, layer):
    return (
        f"❌ **AICGQAF v1.0 — Rejected (Layer {layer})**\n\n"
        f"**Reason:** {reason}\n\n"
        f"| Metric | Value |\n|---|---|\n"
        f"| Critical Issues | {l1.get('issues_critical',0)} |\n"
        f"| High Issues | {l1.get('issues_high',0)} |\n"
        f"| CWE Violations | {', '.join(v.get('cwe_id','?') for v in l1.get('cwe_violations',[])[:5])} |\n\n"
        f"Please fix the above issues and resubmit."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 5. MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="AICGQAF Final Decision Orchestrator")
    parser.add_argument("--mode",             type=str, default="pipeline",
                        choices=["pipeline", "human-decision"])
    parser.add_argument("--review-id",        type=str, required=True)
    parser.add_argument("--layer1-report",    type=str, default="")
    parser.add_argument("--layer2-report",    type=str, default="")
    parser.add_argument("--pr-number",        type=int, default=0)
    parser.add_argument("--repo-url",         type=str, default="")
    parser.add_argument("--github-token",     type=str, default=os.getenv("GITHUB_TOKEN",""))
    # Human decision args
    parser.add_argument("--human-decision",   type=str, default="",
                        choices=["APPROVE","REQUEST_CHANGES","REJECT",""])
    parser.add_argument("--reviewer-id",      type=str, default="")
    parser.add_argument("--comment",          type=str, default="")
    parser.add_argument("--suggested-fix",    type=str, default="")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  AICGQAF v1.0 — Final Decision Orchestrator")
    print(f"  Review ID : {args.review_id}")
    print(f"  Mode      : {args.mode}")
    print(f"{'='*60}\n")

    if args.mode == "human-decision":
        result = process_human_decision(
            args.review_id, args.human_decision,
            args.reviewer_id, args.comment, args.suggested_fix
        )
        print(f"\n[Result] {json.dumps(result, indent=2)}")
        sys.exit(0 if result.get("final_status") == "APPROVED" else 1)

    # ── Pipeline mode ──────────────────────────────────────────────────────────
    l1_report, l2_report = {}, {}

    if args.layer1_report and os.path.exists(args.layer1_report):
        with open(args.layer1_report) as f:
            l1_report = json.load(f)

    if args.layer2_report and os.path.exists(args.layer2_report):
        with open(args.layer2_report) as f:
            l2_report = json.load(f)

    l1_decision = l1_report.get("layer1_decision", "ESCALATE")
    l2_decision = l2_report.get("gate2_decision") if l2_report else None

    path = determine_pipeline_path(l1_decision, l2_decision)
    print(f"[Decision] Pipeline path: {path}")

    ctx = {
        "review_id":     args.review_id,
        "pr_number":     args.pr_number,
        "repo_url":      args.repo_url,
        "github_token":  args.github_token,
        "layer1_report": l1_report,
        "layer2_report": l2_report,
    }

    result = execute_pipeline_path(path, ctx)

    print(f"\n[Final] Status : {result.get('final_status')}")
    print(f"[Final] Merge  : {result.get('merge_allowed')}")
    print(f"[Final] Path   : {result.get('path')}")

    sys.exit(0 if result.get("merge_allowed") else 1)


if __name__ == "__main__":
    main()
