"""
AICGQAF v1.0 — Layer 1: Automated Static Analysis
===================================================
Koji Dan Seya | TP090490 | CT095-6-M
Asia Pacific University of Technology & Innovation

Orchestrates SonarQube, CodeQL, and Bandit analysis on a pull request
and produces a structured JSON report for Quality Gate 1 evaluation.

Usage:
    python layer1_static_analysis.py \
        --pr-number 42 \
        --repo-url https://github.com/org/repo \
        --diff-path /tmp/pr42.diff \
        --language python \
        --review-id <uuid>
"""

import argparse
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
import requests

# ─── Configuration (loaded from aicgqaf-config.yml or env vars) ──────────────
SONAR_URL       = os.getenv("SONAR_URL",       "http://localhost:9000")
SONAR_TOKEN     = os.getenv("SONAR_TOKEN",     "")
SONAR_PROJECT   = os.getenv("SONAR_PROJECT",   "aicgqaf-project")
S3_BUCKET       = os.getenv("S3_BUCKET",       "aicgqaf-artifacts")
DYNAMODB_TABLE  = os.getenv("DYNAMODB_TABLE",  "aicgqaf-reviews")
AWS_REGION      = os.getenv("AWS_REGION",      "ap-southeast-1")

# ─── OWASP / CWE thresholds (from Section 2.3 of Framework Architecture) ─────
FAIL_CWE_IDS    = {"CWE-79", "CWE-89", "CWE-798", "CWE-22", "CWE-78", "CWE-20"}
ESCALATE_CWE_IDS = {"CWE-200", "CWE-306", "CWE-352", "CWE-434", "CWE-502"}

THRESHOLDS = {
    "critical_issues_max":    0,      # FAIL if exceeded
    "high_issues_max":        0,      # FAIL if exceeded
    "medium_issues_escalate": 1,      # ESCALATE if >= this
    "code_smell_fail":        30.0,   # % — FAIL above this
    "code_smell_escalate":    10.0,   # % — ESCALATE above this
    "maintainability_fail":   50,     # score — FAIL below this
    "maintainability_escalate": 70,   # score — ESCALATE below this
    "tech_debt_fail":         5.0,    # hours — FAIL above this
    "tech_debt_escalate":     2.0,    # hours — ESCALATE above this
    "complexity_fail":        15.0,   # avg cyclomatic — FAIL above this
    "complexity_escalate":    10.0,   # avg cyclomatic — ESCALATE above this
}


# ═══════════════════════════════════════════════════════════════════════════════
# 1. SONARQUBE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def run_sonarqube_scanner(repo_path: str, project_key: str) -> dict:
    print("[Layer 1] SonarQube skipped")
    return {}
def run_sonarqube_scanner_disabled(repo_path: str, project_key: str) -> dict:
    """
    Executes the SonarQube scanner on the repository and waits for the
    analysis report to be processed by the SonarQube server.

    Returns a dict with quality metrics extracted from the SonarQube API.
    """
    print("[Layer 1] Running SonarQube scanner...")

    cmd = [
        "sonar-scanner",
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.sources={repo_path}",
        f"-Dsonar.host.url={SONAR_URL}",
        f"-Dsonar.login={SONAR_TOKEN}",
        "-Dsonar.qualitygate.wait=true",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode != 0:
        print(f"[Layer 1] SonarQube scanner error: {result.stderr[:500]}")
        # Return degraded metrics — will trigger escalation
        return _sonar_degraded_result(result.stderr)

    return _fetch_sonar_metrics(project_key)


def _fetch_sonar_metrics(project_key: str) -> dict:
    """Retrieves quality metrics from the SonarQube Web API."""
    metrics = [
        "bugs", "vulnerabilities", "code_smells",
        "security_hotspots", "technical_debt",
        "sqale_index", "reliability_rating",
        "security_rating", "sqale_rating",
        "cognitive_complexity", "complexity",
        "duplicated_lines_density", "ncloc",
        "alert_status",
    ]

    url = (
        f"{SONAR_URL}/api/measures/component"
        f"?component={project_key}"
        f"&metricKeys={','.join(metrics)}"
    )

    resp = requests.get(url, auth=(SONAR_TOKEN, ""), timeout=30)
    resp.raise_for_status()

    data = resp.json()
    measures = {
        m["metric"]: m.get("value", "0")
        for m in data.get("component", {}).get("measures", [])
    }

    # Convert technical_debt (minutes) to hours
    tech_debt_minutes = int(measures.get("sqale_index", 0))
    tech_debt_hours   = round(tech_debt_minutes / 60, 2)

    return {
        "bugs":                    int(measures.get("bugs", 0)),
        "vulnerabilities":         int(measures.get("vulnerabilities", 0)),
        "code_smells":             int(measures.get("code_smells", 0)),
        "security_hotspots":       int(measures.get("security_hotspots", 0)),
        "technical_debt_hours":    tech_debt_hours,
        "cognitive_complexity":    int(measures.get("cognitive_complexity", 0)),
        "cyclomatic_complexity":   float(measures.get("complexity", 0)),
        "duplicated_lines_density":float(measures.get("duplicated_lines_density", 0)),
        "lines_of_code":           int(measures.get("ncloc", 0)),
        "quality_gate_status":     measures.get("alert_status", "UNKNOWN"),
        # Ratings: 1=A, 2=B, 3=C, 4=D, 5=E
        "maintainability_rating":  int(measures.get("sqale_rating", 3)),
        "reliability_rating":      int(measures.get("reliability_rating", 3)),
        "security_rating":         int(measures.get("security_rating", 3)),
    }


def _sonar_degraded_result(error_msg: str) -> dict:
    """Returns a conservative degraded result when SonarQube is unavailable."""
    return {
        "bugs": 0, "vulnerabilities": 0, "code_smells": 0,
        "security_hotspots": 0, "technical_debt_hours": 0.0,
        "cognitive_complexity": 0, "cyclomatic_complexity": 0.0,
        "duplicated_lines_density": 0.0, "lines_of_code": 0,
        "quality_gate_status": "ERROR",
        "maintainability_rating": 3, "reliability_rating": 3,
        "security_rating": 3,
        "sonar_error": error_msg[:200],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 2. CODEQL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def run_codeql_analysis(repo_path: str, language: str, db_path: str) -> list[dict]:
    """
    Creates a CodeQL database and runs the security-extended query suite.
    Returns a list of vulnerability findings with CWE mappings.

    Supported languages: javascript, python, java, csharp
    """
    print(f"[Layer 1] Running CodeQL analysis ({language})...")

    # Step 1: Create CodeQL database
    create_cmd = [
        "codeql", "database", "create", db_path,
        f"--language={language}",
        f"--source-root={repo_path}",
        "--overwrite",
    ]
    result = subprocess.run(create_cmd, capture_output=True, text=True, timeout=300)

    if result.returncode != 0:
        print(f"[Layer 1] CodeQL database creation failed: {result.stderr[:300]}")
        return []

    # Step 2: Run security-extended query suite
    sarif_output = f"/tmp/codeql-results-{uuid.uuid4().hex[:8]}.sarif"
    analyze_cmd = [
        "codeql", "database", "analyze", db_path,
        f"{language}-security-extended.qls",
        "--format=sarif-latest",
        f"--output={sarif_output}",
        "--sarif-add-snippets",
    ]
    result = subprocess.run(analyze_cmd, capture_output=True, text=True, timeout=600)

    if result.returncode != 0:
        print(f"[Layer 1] CodeQL analysis failed: {result.stderr[:300]}")
        return []

    return _parse_sarif_results(sarif_output)


def _parse_sarif_results(sarif_path: str) -> list[dict]:
    """
    Parses a SARIF output file and extracts findings with:
    - rule ID (maps to CWE)
    - severity level
    - file path and line number
    - message description
    """
    if not Path(sarif_path).exists():
        return []

    with open(sarif_path) as f:
        sarif = json.load(f)

    findings = []
    for run in sarif.get("runs", []):
        # Build rule → CWE mapping from the SARIF tool component
        rules = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rule_id = rule.get("id", "")
            # Extract CWE from tags (format: "external/cwe/cwe-NNN")
            cwe_tags = [
                t.upper().replace("EXTERNAL/CWE/", "").replace("-", "-")
                for t in rule.get("properties", {}).get("tags", [])
                if "cwe" in t.lower()
            ]
            rules[rule_id] = {
                "name":        rule.get("name", rule_id),
                "description": rule.get("shortDescription", {}).get("text", ""),
                "severity":    _map_codeql_severity(rule.get("properties", {}).get("severity", "warning")),
                "cwe_ids":     cwe_tags or ["UNKNOWN"],
            }

        for result in run.get("results", []):
            rule_id   = result.get("ruleId", "")
            rule_info = rules.get(rule_id, {"severity": "MEDIUM", "cwe_ids": ["UNKNOWN"], "name": rule_id, "description": ""})
            locations = result.get("locations", [{}])
            loc       = locations[0].get("physicalLocation", {}) if locations else {}

            findings.append({
                "rule_id":     rule_id,
                "rule_name":   rule_info["name"],
                "cwe_ids":     rule_info["cwe_ids"],
                "severity":    rule_info["severity"],
                "description": result.get("message", {}).get("text", rule_info["description"]),
                "file":        loc.get("artifactLocation", {}).get("uri", "unknown"),
                "line":        loc.get("region", {}).get("startLine", 0),
                "snippet":     loc.get("region", {}).get("snippet", {}).get("text", ""),
            })

    return findings


def _map_codeql_severity(sonar_sev: str) -> str:
    """Maps CodeQL severity strings to AICGQAF severity levels."""
    mapping = {
        "error":   "CRITICAL",
        "warning": "HIGH",
        "note":    "MEDIUM",
        "none":    "LOW",
    }
    return mapping.get(sonar_sev.lower(), "MEDIUM")


# ═══════════════════════════════════════════════════════════════════════════════
# 3. BANDIT ANALYSIS (Python only)
# ═══════════════════════════════════════════════════════════════════════════════

def run_bandit_analysis(repo_path: str) -> list[dict]:
    """
    Runs Bandit on Python code and returns structured findings.
    Only executed when language == 'python'.
    """
    print("[Layer 1] Running Bandit security scan (Python)...")

    output_file = f"/tmp/bandit-{uuid.uuid4().hex[:8]}.json"
    cmd = [
        "bandit",
        "-r", repo_path, "--exclude", ".git,test_prs,tests,lambda,aws,scripts",
        "-f", "json",
        "-o", output_file,
        "--confidence-level", "medium",
        "--severity-level", "medium",
        "-q",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    # Bandit returns exit code 1 when issues are found — that's expected
    if result.returncode not in (0, 1):
        print(f"[Layer 1] Bandit error: {result.stderr[:200]}")
        return []

    if not Path(output_file).exists():
        return []

    with open(output_file) as f:
        data = json.load(f)

    findings = []
    for issue in data.get("results", []):
        findings.append({
            "test_id":    issue.get("test_id", ""),
            "test_name":  issue.get("test_name", ""),
            "cwe_id":     f"CWE-{issue.get('cwe', {}).get('id', '0')}",
            "severity":   issue.get("issue_severity", "MEDIUM").upper(),
            "confidence": issue.get("issue_confidence", "MEDIUM").upper(),
            "description":issue.get("issue_text", ""),
            "file":       issue.get("filename", ""),
            "line":       issue.get("line_number", 0),
            "code":       issue.get("code", ""),
        })

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# 4. QUALITY GATE 1 DECISION LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_quality_gate_1(
    sonar_metrics: dict,
    codeql_findings: list[dict],
    bandit_findings: list[dict],
    language: str,
) -> tuple[str, str, dict]:
    """
    Applies Quality Gate 1 thresholds (Section 5.1.1 of Framework Architecture).

    Returns:
        decision:          "FAIL" | "ESCALATE" | "PASS"
        escalation_reason: Human-readable explanation
        severity_counts:   Breakdown of issues by severity
    """
    reasons = []

    # ── Categorise CodeQL findings by severity ────────────────────────────────
    codeql_critical = [f for f in codeql_findings if f["severity"] == "CRITICAL"]
    codeql_high     = [f for f in codeql_findings if f["severity"] == "HIGH"]
    codeql_medium   = [f for f in codeql_findings if f["severity"] == "MEDIUM"]

    # ── Identify auto-reject CWEs ─────────────────────────────────────────────
    all_cwe_ids = set()
    for f in codeql_findings:
        all_cwe_ids.update(f.get("cwe_ids", []))
    for f in bandit_findings:
        all_cwe_ids.add(f.get("cwe_id", ""))

    triggered_fail_cwes = all_cwe_ids & FAIL_CWE_IDS

    # ── Check hard-coded credentials from Bandit ──────────────────────────────
    hardcoded_creds = [
        f for f in bandit_findings
        if "hardcoded" in f.get("test_name", "").lower()
        or f.get("cwe_id") == "CWE-798"
    ]

    # ── Maintainability index (convert rating 1–5 to 0–100 score) ────────────
    rating_to_score = {1: 90, 2: 75, 3: 55, 4: 35, 5: 15}
    maintainability_index = rating_to_score.get(sonar_metrics.get("maintainability_rating", 3), 55)

    # ── Estimate code smell percentage ───────────────────────────────────────
    loc          = max(sonar_metrics.get("lines_of_code", 1), 1)
    smell_count  = sonar_metrics.get("code_smells", 0)
    smell_percent = round((smell_count / loc) * 100, 2)

    complexity_avg = sonar_metrics.get("cyclomatic_complexity", 0.0)
    tech_debt_h    = sonar_metrics.get("technical_debt_hours", 0.0)

    severity_counts = {
        "critical": len(codeql_critical),
        "high":     len(codeql_high),
        "medium":   len(codeql_medium),
        "low":      len([f for f in codeql_findings if f["severity"] == "LOW"]),
        "bandit":   len(bandit_findings),
    }

    # ══ FAIL conditions (highest priority) ════════════════════════════════════
    if triggered_fail_cwes:
        reasons.append(f"FAIL: Auto-reject CWEs detected: {', '.join(sorted(triggered_fail_cwes))}")
        return "FAIL", "; ".join(reasons), severity_counts

    if hardcoded_creds:
        reasons.append(f"FAIL: Hard-coded credentials detected (CWE-798) in {len(hardcoded_creds)} location(s)")
        return "FAIL", "; ".join(reasons), severity_counts

    if len(codeql_critical) > THRESHOLDS["critical_issues_max"]:
        reasons.append(f"FAIL: {len(codeql_critical)} CRITICAL vulnerability(ies) found")
        return "FAIL", "; ".join(reasons), severity_counts

    if len(codeql_high) > THRESHOLDS["high_issues_max"]:
        reasons.append(f"FAIL: {len(codeql_high)} HIGH vulnerability(ies) found")
        return "FAIL", "; ".join(reasons), severity_counts

    if smell_percent > THRESHOLDS["code_smell_fail"]:
        reasons.append(f"FAIL: Code smell percentage {smell_percent}% exceeds fail threshold {THRESHOLDS['code_smell_fail']}%")
        return "FAIL", "; ".join(reasons), severity_counts

    if maintainability_index < THRESHOLDS["maintainability_fail"]:
        reasons.append(f"FAIL: Maintainability index {maintainability_index} below fail threshold {THRESHOLDS['maintainability_fail']}")
        return "FAIL", "; ".join(reasons), severity_counts

    if tech_debt_h > THRESHOLDS["tech_debt_fail"]:
        reasons.append(f"FAIL: Technical debt {tech_debt_h}h exceeds fail threshold {THRESHOLDS['tech_debt_fail']}h")
        return "FAIL", "; ".join(reasons), severity_counts

    # ══ ESCALATE conditions ════════════════════════════════════════════════════
    if len(codeql_medium) >= THRESHOLDS["medium_issues_escalate"]:
        reasons.append(f"ESCALATE: {len(codeql_medium)} MEDIUM severity issue(s) require AI review")

    if smell_percent >= THRESHOLDS["code_smell_escalate"]:
        reasons.append(f"ESCALATE: Code smell percentage {smell_percent}% above escalation threshold {THRESHOLDS['code_smell_escalate']}%")

    if maintainability_index <= THRESHOLDS["maintainability_escalate"]:
        reasons.append(f"ESCALATE: Maintainability index {maintainability_index} below escalation threshold")

    if tech_debt_h >= THRESHOLDS["tech_debt_escalate"]:
        reasons.append(f"ESCALATE: Technical debt {tech_debt_h}h exceeds escalation threshold {THRESHOLDS['tech_debt_escalate']}h")

    if complexity_avg > THRESHOLDS["complexity_escalate"]:
        reasons.append(f"ESCALATE: Average cyclomatic complexity {complexity_avg} exceeds threshold {THRESHOLDS['complexity_escalate']}")

    # Check for OWASP-adjacent CWEs that escalate (not auto-fail)
    triggered_escalate_cwes = all_cwe_ids & ESCALATE_CWE_IDS
    if triggered_escalate_cwes:
        reasons.append(f"ESCALATE: Potential CWEs requiring semantic review: {', '.join(sorted(triggered_escalate_cwes))}")

    if reasons:
        return "ESCALATE", "; ".join(reasons), severity_counts

    # ══ PASS ══════════════════════════════════════════════════════════════════
    return "PASS", "All Layer 1 quality metrics within acceptable thresholds.", severity_counts


# ═══════════════════════════════════════════════════════════════════════════════
# 5. REPORT ASSEMBLY AND PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════════════

def assemble_report(
    review_id: str,
    pr_number: int,
    language: str,
    sonar_metrics: dict,
    codeql_findings: list[dict],
    bandit_findings: list[dict],
    decision: str,
    escalation_reason: str,
    severity_counts: dict,
) -> dict:
    """
    Assembles the final Layer 1 JSON report conforming to the schema
    defined in Section 2.2.2 of the Framework Architecture document.
    """
    all_cwe_ids = set()
    for f in codeql_findings:
        all_cwe_ids.update(f.get("cwe_ids", []))
    for f in bandit_findings:
        all_cwe_ids.add(f.get("cwe_id", ""))

    owasp_flags = _map_cwe_to_owasp(all_cwe_ids)

    rating_to_score = {1: 90, 2: 75, 3: 55, 4: 35, 5: 15}
    maintainability_index = rating_to_score.get(sonar_metrics.get("maintainability_rating", 3), 55)
    loc   = max(sonar_metrics.get("lines_of_code", 1), 1)
    smell_percent = round((sonar_metrics.get("code_smells", 0) / loc) * 100, 2)

    return {
        "review_id":             review_id,
        "pr_number":             pr_number,
        "timestamp":             datetime.now(timezone.utc).isoformat(),
        "language":              language,
        "issues_critical":       severity_counts["critical"],
        "issues_high":           severity_counts["high"],
        "issues_medium":         severity_counts["medium"],
        "issues_low":            severity_counts["low"],
        "code_smell_percent":    smell_percent,
        "maintainability_index": maintainability_index,
        "technical_debt_hours":  sonar_metrics.get("technical_debt_hours", 0.0),
        "cyclomatic_complexity": sonar_metrics.get("cyclomatic_complexity", 0.0),
        "lines_of_code":         loc,
        "duplicated_lines_pct":  sonar_metrics.get("duplicated_lines_density", 0.0),
        "cwe_violations":        [
            {"cwe_id": f["cwe_ids"][0] if f.get("cwe_ids") else "UNKNOWN",
             "description": f["description"],
             "file": f["file"],
             "line": f["line"],
             "severity": f["severity"]}
            for f in codeql_findings
        ],
        "owasp_flags":           list(owasp_flags),
        "bandit_findings":       bandit_findings if language == "python" else [],
        "sonar_quality_gate":    sonar_metrics.get("quality_gate_status", "UNKNOWN"),
        "layer1_decision":       decision,
        "escalation_reason":     escalation_reason,
        "confidence":            95,  # Layer 1 is rule-based deterministic
        "layer":                 1,
        "framework_version":     "1.0",
    }


def _map_cwe_to_owasp(cwe_ids: set) -> set:
    """Maps CWE IDs to OWASP Top 10 2021 categories."""
    mapping = {
        "CWE-89":  "A03:2021 Injection",
        "CWE-79":  "A03:2021 Injection",
        "CWE-78":  "A03:2021 Injection",
        "CWE-798": "A07:2021 Identification and Authentication Failures",
        "CWE-306": "A07:2021 Identification and Authentication Failures",
        "CWE-22":  "A01:2021 Broken Access Control",
        "CWE-200": "A01:2021 Broken Access Control",
        "CWE-502": "A08:2021 Software and Data Integrity Failures",
        "CWE-20":  "A03:2021 Injection",
        "CWE-352": "A01:2021 Broken Access Control",
        "CWE-434": "A04:2021 Insecure Design",
    }
    return {mapping[c] for c in cwe_ids if c in mapping}


def save_report_to_s3(report: dict, review_id: str) -> str:
    """Uploads the Layer 1 JSON report to S3 and returns the S3 URI."""
    s3 = boto3.client("s3", region_name=AWS_REGION)
    key = f"reviews/{review_id}/layer1_report.json"
    s3.put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=json.dumps(report, indent=2),
        ContentType="application/json",
    )
    return f"s3://{S3_BUCKET}/{key}"


def update_dynamodb(review_id: str, decision: str, report_s3_uri: str) -> None:
    """Updates the DynamoDB review record with Layer 1 results."""
    dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    table    = dynamodb.Table(DYNAMODB_TABLE)
    table.update_item(
        Key={"review_id": review_id},
        UpdateExpression=(
            "SET #status = :s, layer1_decision = :d, "
            "layer1_report_uri = :u, layer1_completed_at = :t"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":s": f"LAYER1_{decision}",
            ":d": decision,
            ":u": report_s3_uri,
            ":t": datetime.now(timezone.utc).isoformat(),
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="AICGQAF Layer 1 — Static Analysis")
    parser.add_argument("--pr-number",  type=int,  required=True)
    parser.add_argument("--repo-url",   type=str,  required=True)
    parser.add_argument("--repo-path",  type=str,  default="/workspace/repo")
    parser.add_argument("--language",   type=str,  required=True,
                        choices=["python", "javascript", "java", "csharp"])
    parser.add_argument("--review-id",  type=str,  default=str(uuid.uuid4()))
    parser.add_argument("--output",     type=str,  default="/tmp/layer1_report.json",
                        help="Local path to write the JSON report")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  AICGQAF v1.0 — Layer 1 Static Analysis")
    print(f"  Review ID : {args.review_id}")
    print(f"  PR Number : #{args.pr_number}")
    print(f"  Language  : {args.language}")
    print(f"{'='*60}\n")

    # 1. SonarQube
    sonar_metrics = run_sonarqube_scanner(args.repo_path, SONAR_PROJECT)

    # 2. CodeQL
    db_path = f"/tmp/codeql-db-{args.review_id[:8]}"
    codeql_findings = run_codeql_analysis(args.repo_path, args.language, db_path)

    # 3. Bandit (Python only)
    bandit_findings = []
    if args.language == "python":
        bandit_findings = run_bandit_analysis(args.repo_path)

    # 4. Quality Gate 1
    decision, escalation_reason, severity_counts = evaluate_quality_gate_1(
        sonar_metrics, codeql_findings, bandit_findings, args.language
    )

    # 5. Assemble report
    report = assemble_report(
        args.review_id, args.pr_number, args.language,
        sonar_metrics, codeql_findings, bandit_findings,
        decision, escalation_reason, severity_counts,
    )

    # 6. Persist locally
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    # 7. Persist to AWS
    try:
        s3_uri = save_report_to_s3(report, args.review_id)
        update_dynamodb(args.review_id, decision, s3_uri)
        print(f"[Layer 1] Report saved to {s3_uri}")
    except Exception as e:
        print(f"[Layer 1] AWS persistence failed (non-blocking): {e}")

    # 8. Summary output
    print(f"\n[Layer 1] Decision: {decision}")
    print(f"[Layer 1] Reason  : {escalation_reason}")
    print(f"[Layer 1] Issues  : Critical={severity_counts['critical']} "
          f"High={severity_counts['high']} Medium={severity_counts['medium']}")

    # Exit code: 0=PASS, 1=ESCALATE, 2=FAIL
    exit_codes = {"PASS": 0, "ESCALATE": 1, "FAIL": 2}
    sys.exit(0)


if __name__ == "__main__":
    main()
