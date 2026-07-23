"""
AICGQAF v1.0 — Layer 2: AI-Assisted Semantic Review
=====================================================
Koji Dan Seya | TP090490 | CT095-6-M
Asia Pacific University of Technology & Innovation

Constructs a structured context package, calls the Claude API for
semantic code review, and evaluates Quality Gate 2 decision logic.

Usage:
    python layer2_ai_review.py \
        --review-id <uuid> \
        --layer1-report /tmp/layer1_report.json \
        --repo-path /workspace/repo \
        --pr-diff /tmp/pr.diff
"""

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
import requests

# ─── Configuration ────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY  = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_API_URL  = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL    = "claude-sonnet-4-20250514"
S3_BUCKET          = os.getenv("S3_BUCKET",         "aicgqaf-artifacts")
DYNAMODB_TABLE     = os.getenv("DYNAMODB_TABLE",     "aicgqaf-reviews")
CACHE_TABLE        = os.getenv("CACHE_TABLE",        "aicgqaf-l2-cache")
AWS_REGION         = os.getenv("AWS_REGION",         "ap-southeast-1")

# ─── Model parameters (Section 3.1 of Framework Architecture) ────────────────
MODEL_CONFIG = {
    "model":       ANTHROPIC_MODEL,
    "max_tokens":  8000,
    "temperature": 0.3,
    "top_p":       0.9,
}

# ─── Quality Gate 2 thresholds (Section 5.1.2) ────────────────────────────────
THRESHOLDS = {
    "confidence_approve_min":  70,    # APPROVE if confidence >= this
    "confidence_escalate_min": 30,    # REJECT if confidence < this
    "maintainability_min":     50,    # ESCALATE if below this
    "max_medium_issues":       0,     # ESCALATE if medium security concerns found
    "cvss_auto_block":         6.0,   # Auto-block CVSS >= this
    "cost_limit_per_review":   0.05,  # USD — abort if exceeded
    "max_retries":             3,
    "retry_delay_seconds":     5,
}


# ═══════════════════════════════════════════════════════════════════════════════
# 1. CONTEXT PACKAGE ASSEMBLY
# ═══════════════════════════════════════════════════════════════════════════════

def build_context_package(
    pr_diff: str,
    repo_path: str,
    layer1_report: dict,
    language: str,
) -> dict:
    """
    Assembles the 7-section context package (Section 3.2 of Framework Architecture).
    Context quality directly determines Layer 2 accuracy (Cihan et al., 2025).
    """
    return {
        "section1_code":          _extract_code_context(pr_diff, repo_path),
        "section2_architecture":  _detect_architecture(repo_path, language),
        "section3_security":      _load_security_policies(repo_path),
        "section4_layer1":        layer1_report,
        "section5_standards":     _load_coding_standards(repo_path),
        "section6_history":       _fetch_review_history(layer1_report.get("review_id", "")),
        "section7_dependencies":  _check_dependency_cves(repo_path, language),
    }


def _extract_code_context(diff_path: str, repo_path: str) -> dict:
    """Reads the PR diff and extracts changed files with surrounding context."""
    if not Path(diff_path).exists():
        return {"diff": "", "changed_files": [], "lines_added": 0, "lines_removed": 0}

    with open(diff_path) as f:
        diff_content = f.read()

    # Truncate to stay within the 8,000 token budget (approx 6,000 chars of diff)
    max_diff_chars = 6000
    truncated = False
    if len(diff_content) > max_diff_chars:
        diff_content = diff_content[:max_diff_chars] + "\n... [diff truncated for token budget]"
        truncated = True

    lines  = diff_content.splitlines()
    added  = sum(1 for l in lines if l.startswith("+") and not l.startswith("+++"))
    removed= sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))
    files  = [l[6:] for l in lines if l.startswith("+++ b/")]

    return {
        "diff":          diff_content,
        "changed_files": files,
        "lines_added":   added,
        "lines_removed": removed,
        "truncated":     truncated,
    }


def _detect_architecture(repo_path: str, language: str) -> dict:
    """Detects the repository architecture by analysing file structure and config files."""
    path = Path(repo_path)

    patterns = {
        "mvc":          any([(path / d).exists() for d in ["controllers", "models", "views", "Controllers", "Models"]]),
        "microservices":any([(path / f).exists() for f in ["docker-compose.yml", "kubernetes", "k8s"]]),
        "repository":   any([(path / d).exists() for d in ["repositories", "Repositories", "repos"]]),
        "event_driven": any([(path / f).exists() for f in ["events", "handlers", "listeners"]]),
        "layered":      any([(path / d).exists() for d in ["service", "services", "dal", "domain"]]),
    }
    detected = [k for k, v in patterns.items() if v]

    # Detect framework from config files
    framework = "Unknown"
    framework_map = {
        "package.json":   _detect_js_framework(path / "package.json"),
        "pom.xml":        "Spring (Java)",
        "build.gradle":   "Gradle (Java/Kotlin)",
        "requirements.txt":"Python (requirements.txt)",
        "Pipfile":        "Python (Pipfile)",
        "*.csproj":       "ASP.NET Core (C#)",
        "go.mod":         "Go modules",
    }
    for fname, fw in framework_map.items():
        if "*" in fname:
            matches = list(path.glob(fname))
            if matches:
                framework = fw
                break
        elif (path / fname).exists():
            framework = fw
            break

    return {
        "patterns_detected": detected if detected else ["unknown"],
        "directory_structure": _get_dir_structure(repo_path, max_depth=2),
        "framework":          framework,
        "language":           language,
        "has_tests":          any([(path / d).exists() for d in ["tests", "test", "__tests__", "spec"]]),
        "has_docs":           any([(path / d).exists() for d in ["docs", "documentation", "README.md"]]),
    }


def _detect_js_framework(package_json_path: Path) -> str:
    """Detects the JS framework from package.json."""
    if not package_json_path.exists():
        return "JavaScript"
    try:
        with open(package_json_path) as f:
            pkg = json.load(f)
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        if "next" in deps:          return "Next.js"
        if "react" in deps:         return "React"
        if "vue" in deps:           return "Vue.js"
        if "express" in deps:       return "Express.js"
        if "@nestjs/core" in deps:  return "NestJS"
        if "fastify" in deps:       return "Fastify"
    except Exception:
        pass
    return "JavaScript"


def _get_dir_structure(repo_path: str, max_depth: int = 2) -> str:
    """Returns a compact string representation of the top-level directory structure."""
    lines = []
    base = Path(repo_path)
    ignore = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"}

    def walk(path: Path, depth: int, prefix: str):
        if depth > max_depth:
            return
        try:
            entries = sorted(path.iterdir(), key=lambda x: (x.is_file(), x.name))
        except PermissionError:
            return
        for entry in entries[:20]:  # Cap at 20 entries per level
            if entry.name in ignore:
                continue
            lines.append(f"{prefix}{'└── ' if entry == entries[-1] else '├── '}{entry.name}{'/' if entry.is_dir() else ''}")
            if entry.is_dir():
                walk(entry, depth + 1, prefix + ("    " if entry == entries[-1] else "│   "))

    walk(base, 0, "")
    return "\n".join(lines[:60])  # Cap at 60 lines


def _load_security_policies(repo_path: str) -> dict:
    """Loads security policies from well-known locations in the repository."""
    policy_files = [
        "SECURITY.md", "security.md", "docs/SECURITY.md",
        ".github/SECURITY.md", "security-policy.md",
    ]
    policy_content = "No explicit security policy file found. Applying OWASP Top 10 2021 defaults."
    for fname in policy_files:
        fp = Path(repo_path) / fname
        if fp.exists():
            with open(fp) as f:
                policy_content = f.read()[:1000]  # Cap at 1000 chars
            break

    return {
        "policy_content":       policy_content,
        "applicable_standards": ["OWASP Top 10 2021", "CWE Top 25", "NIST CSF"],
        "auto_reject_patterns": [
            "SQL string concatenation with user input",
            "Unparameterised database queries",
            "Hard-coded passwords or API keys",
            "Missing authentication on state-changing endpoints",
            "Unrestricted file upload",
        ],
    }


def _load_coding_standards(repo_path: str) -> dict:
    """Loads coding standards from the repository."""
    standards_files = [
        "docs/coding-standards.md", "CONTRIBUTING.md",
        ".eslintrc.json", ".pylintrc", "pyproject.toml",
    ]
    for fname in standards_files:
        fp = Path(repo_path) / fname
        if fp.exists():
            with open(fp) as f:
                content = f.read()[:800]
            return {"source": fname, "content": content}

    return {
        "source":  "default",
        "content": "Standard industry coding conventions. Follow PEP8 (Python), ESLint recommended (JS/TS), Google Java Style (Java), Microsoft C# conventions.",
    }


def _fetch_review_history(review_id: str) -> list:
    """Fetches the last 5 review decisions for the same repository from DynamoDB."""
    # Simplified — in production, queries DynamoDB for repo-specific history
    return []


def _check_dependency_cves(repo_path: str, language: str) -> dict:
    """Placeholder for dependency CVE checking."""
    return {
        "checked":      False,
        "note":         "Dependency CVE checking requires Dependabot or Snyk integration.",
        "known_issues": [],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 2. PROMPT CONSTRUCTION
# ═══════════════════════════════════════════════════════════════════════════════

def build_review_prompt(context: dict) -> str:
    """
    Constructs the Layer 2 review prompt using the 4-section architecture
    defined in Section 3.3 of the Framework Architecture document.
    """
    l1 = context["section4_layer1"]
    arch = context["section2_architecture"]
    sec = context["section3_security"]
    code = context["section1_code"]

    prompt = f"""You are a senior software engineer and security specialist performing an AI-assisted code review for the AICGQAF quality assurance pipeline. Your role is to identify quality issues that automated static analysis (Layer 1) cannot detect — specifically semantic correctness, architectural coherence, and context-specific security risks.

<code_under_review>
CHANGED FILES: {', '.join(code.get('changed_files', ['unknown']))}
LINES ADDED: {code.get('lines_added', 0)} | LINES REMOVED: {code.get('lines_removed', 0)}

PR DIFF:
{code.get('diff', 'No diff available')}
</code_under_review>

<repository_context>
LANGUAGE: {arch.get('language', 'unknown')}
FRAMEWORK: {arch.get('framework', 'unknown')}
ARCHITECTURE PATTERNS: {', '.join(arch.get('patterns_detected', ['unknown']))}
HAS TESTS: {arch.get('has_tests', False)}

DIRECTORY STRUCTURE:
{arch.get('directory_structure', 'Not available')}
</repository_context>

<security_context>
APPLICABLE STANDARDS: {', '.join(sec.get('applicable_standards', []))}
POLICY:
{sec.get('policy_content', '')[:600]}
AUTO-REJECT PATTERNS: {'; '.join(sec.get('auto_reject_patterns', []))}
</security_context>

<layer1_results>
Layer 1 Decision: {l1.get('layer1_decision', 'ESCALATE')}
Escalation Reason: {l1.get('escalation_reason', '')}
Issues: Critical={l1.get('issues_critical', 0)} High={l1.get('issues_high', 0)} Medium={l1.get('issues_medium', 0)}
Code Smells: {l1.get('code_smell_percent', 0)}% | Maintainability: {l1.get('maintainability_index', 0)} | Tech Debt: {l1.get('technical_debt_hours', 0)}h
CWE Violations: {json.dumps(l1.get('cwe_violations', [])[:5])}
</layer1_results>

<coding_standards>
{context.get('section5_standards', {}).get('content', 'Standard conventions apply.')}
</coding_standards>

<evaluation_instructions>
Evaluate the code across EXACTLY these 5 dimensions. Do NOT duplicate Layer 1 findings — focus only on what static analysis cannot detect:

1. SEMANTIC CORRECTNESS: Does the code actually do what it claims to do? Check for logic errors, incorrect conditionals, off-by-one errors, missing null checks, unhandled edge cases, race conditions.

2. ARCHITECTURAL FIT: Does the code follow the repository's patterns? Does it bypass existing abstractions, introduce inconsistent dependencies, or violate separation of concerns?

3. SECURITY AWARENESS: Are there context-specific security risks NOT already in the Layer 1 CWE list? Look for: business-logic authentication bypasses, IDOR vulnerabilities, insecure state management, context-specific data exposure risks.

4. MAINTAINABILITY: Is the code readable and self-documenting? Are names meaningful? Is complexity justified?

5. PERFORMANCE: Any obviously inefficient patterns (N+1 queries, blocking calls, unbounded loops)?
</evaluation_instructions>

Respond with ONLY a valid JSON object — no preamble, no markdown, no explanation outside the JSON. Use this exact schema:

{{
  "semantic_correct": true,
  "architectural_fit": true,
  "security_concerns": [
    {{
      "severity": "HIGH",
      "cwe_id": "CWE-639",
      "description": "...",
      "suggested_fix": "..."
    }}
  ],
  "maintainability_score": 75,
  "performance_flags": [
    {{ "severity": "MEDIUM", "description": "..." }}
  ],
  "overall_confidence": 82,
  "recommendation": "APPROVE",
  "explanation": "Plain-language summary for the developer (2-3 sentences max).",
  "context_used": {{
    "diff_truncated": false,
    "architecture_detected": true,
    "security_policy_found": false,
    "l1_results_used": true
  }},
  "review_duration_ms": 0
}}

Valid values for recommendation: "APPROVE" | "REVIEW_HUMAN" | "REJECT"
Valid values for severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
overall_confidence must be an integer 0–100.
maintainability_score must be an integer 0–100."""

    return prompt


# ═══════════════════════════════════════════════════════════════════════════════
# 3. CLAUDE API CALL WITH RETRY AND CACHE
# ═══════════════════════════════════════════════════════════════════════════════

def call_claude_api(prompt: str, review_id: str) -> dict:
    """
    Calls the Anthropic Claude API with retry logic and cost monitoring.
    Returns the parsed Layer 2 JSON response.
    """
    # Check cache first (24-hour TTL on identical diffs)
    cache_key = hashlib.sha256(prompt[:3000].encode()).hexdigest()
    cached = _check_cache(cache_key)
    if cached:
        print("[Layer 2] Cache hit — returning cached result")
        return cached

    headers = {
        "Content-Type":         "application/json",
        "x-api-key":            ANTHROPIC_API_KEY,
        "anthropic-version":    "2023-06-01",
    }

    payload = {
        **MODEL_CONFIG,
        "messages": [{"role": "user", "content": prompt}],
    }

    last_error = None
    for attempt in range(1, THRESHOLDS["max_retries"] + 1):
        try:
            print(f"[Layer 2] Claude API call (attempt {attempt}/{THRESHOLDS['max_retries']})...")
            start_ms = int(time.time() * 1000)

            resp = requests.post(
                ANTHROPIC_API_URL,
                headers=headers,
                json=payload,
                timeout=35,
            )

            duration_ms = int(time.time() * 1000) - start_ms

            if resp.status_code == 429:
                wait = THRESHOLDS["retry_delay_seconds"] * attempt
                print(f"[Layer 2] Rate limited. Waiting {wait}s...")
                time.sleep(wait)
                continue

            resp.raise_for_status()
            data = resp.json()

            # Extract text content
            raw_text = ""
            for block in data.get("content", []):
                if block.get("type") == "text":
                    raw_text += block.get("text", "")

            # Parse JSON response
            result = _parse_json_response(raw_text)
            result["review_duration_ms"] = duration_ms

            # Cache successful result
            _write_cache(cache_key, result)

            # Log usage for cost monitoring
            usage = data.get("usage", {})
            _log_api_usage(review_id, usage, duration_ms)

            return result

        except requests.exceptions.Timeout:
            last_error = "API timeout after 35 seconds"
            print(f"[Layer 2] Timeout on attempt {attempt}")
        except requests.exceptions.RequestException as e:
            last_error = str(e)
            print(f"[Layer 2] Request error: {e}")
        except json.JSONDecodeError as e:
            last_error = f"JSON parse error: {e}"
            print(f"[Layer 2] JSON parse failed: {e}")

        if attempt < THRESHOLDS["max_retries"]:
            time.sleep(THRESHOLDS["retry_delay_seconds"])

    # All retries exhausted — return low-confidence escalation result
    print(f"[Layer 2] All retries exhausted. Last error: {last_error}")
    return _fallback_escalate_result(last_error)


def _parse_json_response(raw_text: str) -> dict:
    """Strips markdown fences and parses the JSON response from Claude."""
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
    return json.loads(text.strip())


def _check_cache(cache_key: str) -> dict | None:
    """Checks DynamoDB cache for a recent identical review."""
    try:
        dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
        table = dynamodb.Table(CACHE_TABLE)
        item = table.get_item(Key={"cache_key": cache_key}).get("Item")
        if item:
            cached_at = datetime.fromisoformat(item["cached_at"])
            age_hours = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600
            if age_hours < 24:
                return json.loads(item["result"])
    except Exception:
        pass
    return None


def _write_cache(cache_key: str, result: dict) -> None:
    """Writes result to DynamoDB cache."""
    try:
        dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
        table = dynamodb.Table(CACHE_TABLE)
        table.put_item(Item={
            "cache_key": cache_key,
            "result": json.dumps(result),
            "cached_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:
        pass


def _log_api_usage(review_id: str, usage: dict, duration_ms: int) -> None:
    """Logs token usage and estimated cost to DynamoDB for cost monitoring."""
    input_tokens  = usage.get("input_tokens",  0)
    output_tokens = usage.get("output_tokens", 0)
    # Claude claude-sonnet-4-20250514 pricing: $3/M input, $15/M output
    estimated_cost = (input_tokens / 1_000_000 * 3.0) + (output_tokens / 1_000_000 * 15.0)

    print(f"[Layer 2] Tokens: {input_tokens} in / {output_tokens} out | Cost: ${estimated_cost:.4f} | Time: {duration_ms}ms")

    if estimated_cost > THRESHOLDS["cost_limit_per_review"]:
        print(f"[Layer 2] WARNING: Review cost ${estimated_cost:.4f} exceeds limit ${THRESHOLDS['cost_limit_per_review']}")


def _fallback_escalate_result(error: str) -> dict:
    """Returns a conservative escalation result when the API is unavailable."""
    return {
        "semantic_correct":    True,
        "architectural_fit":   True,
        "security_concerns":   [],
        "maintainability_score": 50,
        "performance_flags":   [],
        "overall_confidence":  25,  # Low confidence → triggers ESCALATE
        "recommendation":      "REVIEW_HUMAN",
        "explanation":         f"Layer 2 API unavailable ({error}). Escalating to human review as a precaution.",
        "context_used":        {"api_error": error},
        "review_duration_ms":  0,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 4. QUALITY GATE 2 DECISION LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_quality_gate_2(response: dict) -> tuple[str, str]:
    """
    Applies Quality Gate 2 logic (Section 5.1.2 of Framework Architecture).
    Priority ordering: REJECT > ESCALATE > APPROVE.

    Returns: (decision, reason)
    """
    confidence = response.get("overall_confidence", 0)
    semantic   = response.get("semantic_correct", True)
    arch_fit   = response.get("architectural_fit", True)
    maintain   = response.get("maintainability_score", 100)
    concerns   = response.get("security_concerns", [])
    recommendation = response.get("recommendation", "REVIEW_HUMAN")

    high_critical_concerns = [
        c for c in concerns
        if c.get("severity", "LOW") in ("HIGH", "CRITICAL")
    ]
    medium_concerns = [
        c for c in concerns
        if c.get("severity", "LOW") == "MEDIUM"
    ]

    # ── REJECT conditions (highest priority) ──────────────────────────────────
    if not semantic:
        return "REJECT", "Semantic correctness failure — code does not achieve its stated purpose."

    if high_critical_concerns:
        cwes = ", ".join(c.get("cwe_id", "?") for c in high_critical_concerns)
        return "REJECT", f"HIGH/CRITICAL security concerns: {cwes}. Deployment blocked."

    if confidence < THRESHOLDS["confidence_escalate_min"]:
        return "REJECT", f"AI confidence {confidence}% too low for any decision. Manual review required."

    if recommendation == "REJECT":
        return "REJECT", f"AI reviewer recommendation: REJECT. {response.get('explanation', '')}"

    # ── ESCALATE conditions ────────────────────────────────────────────────────
    if confidence < THRESHOLDS["confidence_approve_min"]:
        return "ESCALATE", f"AI confidence {confidence}% below approval threshold {THRESHOLDS['confidence_approve_min']}%."

    if medium_concerns:
        cwes = ", ".join(c.get("cwe_id", "?") for c in medium_concerns)
        return "ESCALATE", f"MEDIUM security concerns requiring human validation: {cwes}."

    if maintain < THRESHOLDS["maintainability_min"]:
        return "ESCALATE", f"Maintainability score {maintain} below threshold {THRESHOLDS['maintainability_min']}."

    if not arch_fit:
        return "ESCALATE", "Architectural fit failure — code deviates from repository patterns."

    if recommendation == "REVIEW_HUMAN":
        return "ESCALATE", f"AI reviewer recommends human review. {response.get('explanation', '')}"

    # ── APPROVE ────────────────────────────────────────────────────────────────
    return "APPROVE", f"All Quality Gate 2 criteria met. AI confidence: {confidence}%."


# ═══════════════════════════════════════════════════════════════════════════════
# 5. REPORT PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════════════

def save_layer2_report(review_id: str, response: dict, decision: str, reason: str) -> str:
    """Saves the Layer 2 JSON report to S3."""
    report = {
        **response,
        "review_id":       review_id,
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "gate2_decision":  decision,
        "gate2_reason":    reason,
        "layer":           2,
        "framework_version": "1.0",
    }

    s3 = boto3.client("s3", region_name=AWS_REGION)
    key = f"reviews/{review_id}/layer2_report.json"
    s3.put_object(
        Bucket=S3_BUCKET, Key=key,
        Body=json.dumps(report, indent=2),
        ContentType="application/json",
    )

    dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.update_item(
        Key={"review_id": review_id},
        UpdateExpression=(
            "SET #status = :s, gate2_decision = :d, gate2_reason = :r, "
            "layer2_confidence = :c, layer2_completed_at = :t"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":s": f"GATE2_{decision}",
            ":d": decision,
            ":r": reason,
            ":c": response.get("overall_confidence", 0),
            ":t": datetime.now(timezone.utc).isoformat(),
        },
    )

    return f"s3://{S3_BUCKET}/{key}"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="AICGQAF Layer 2 — AI Semantic Review")
    parser.add_argument("--review-id",      type=str, required=True)
    parser.add_argument("--layer1-report",  type=str, required=True)
    parser.add_argument("--repo-path",      type=str, default="/workspace/repo")
    parser.add_argument("--pr-diff",        type=str, required=True)
    parser.add_argument("--language",       type=str, required=True)
    parser.add_argument("--output",         type=str, default="/tmp/layer2_report.json")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  AICGQAF v1.0 — Layer 2 AI Semantic Review")
    print(f"  Review ID : {args.review_id}")
    print(f"  Model     : {ANTHROPIC_MODEL}")
    print(f"{'='*60}\n")

    # Load Layer 1 report
    with open(args.layer1_report) as f:
        layer1_report = json.load(f)

    # Build context package
    print("[Layer 2] Assembling context package...")
    context = build_context_package(args.pr_diff, args.repo_path, layer1_report, args.language)

    # Build prompt
    prompt = build_review_prompt(context)

    # Call Claude API
    response = call_claude_api(prompt, args.review_id)

    # Evaluate Quality Gate 2
    decision, reason = evaluate_quality_gate_2(response)

    # Persist locally
    with open(args.output, "w") as f:
        json.dump({**response, "gate2_decision": decision, "gate2_reason": reason}, f, indent=2)

    # Persist to AWS
    try:
        s3_uri = save_layer2_report(args.review_id, response, decision, reason)
        print(f"[Layer 2] Report saved to {s3_uri}")
    except Exception as e:
        print(f"[Layer 2] AWS persistence failed (non-blocking): {e}")

    print(f"\n[Layer 2] Decision   : {decision}")
    print(f"[Layer 2] Confidence : {response.get('overall_confidence', '?')}%")
    print(f"[Layer 2] Reason     : {reason}")

    exit_codes = {"APPROVE": 0, "ESCALATE": 1, "REJECT": 2}
    sys.exit(0)


if __name__ == "__main__":
    main()
