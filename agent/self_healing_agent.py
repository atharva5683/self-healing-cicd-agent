"""
Self-Healing CI/CD Pipeline Agent
----------------------------------
Analyses pipeline failures across:
- Dependency installation errors
- Lint failures (flake8)
- Test failures (pytest)
- Docker build failures

Supports multiple AI providers:
- Anthropic Claude (production)
- Google Gemini (free tier / testing)

Configure via AI_PROVIDER environment variable: "claude" or "gemini"

Posts structured diagnosis + fix suggestions as a PR comment.
Author: Ayushi Vasishtha
"""

import os
import sys
import json
import re
import requests
from typing import Optional

# ── Config ────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
GEMINI_API_KEY    = os.environ.get("GEMINI_API_KEY")
AI_PROVIDER       = os.environ.get("AI_PROVIDER", "claude").lower()
GITHUB_TOKEN      = os.environ.get("GITHUB_TOKEN")
REPO_NAME         = os.environ.get("REPO_NAME")
PR_NUMBER         = os.environ.get("PR_NUMBER")
COMMIT_SHA        = os.environ.get("COMMIT_SHA", "unknown")
RUN_ID            = os.environ.get("RUN_ID", "unknown")
LOG_FILE          = "combined-logs.txt"

SYSTEM_PROMPT = """You are an expert DevOps engineer and CI/CD specialist.
Your job is to analyse pipeline failure logs and provide:
1. A clear root cause diagnosis
2. Specific, actionable fix suggestions with code examples where possible
3. Prevention recommendations

You handle these failure types:
- Dependency/package installation failures
- Lint/code style failures (flake8, pylint)
- Unit/integration test failures (pytest)
- Docker build failures

Always respond in valid JSON with this exact structure:
{
  "severity": "critical|high|medium|low",
  "failure_types": ["list of detected failure types"],
  "root_cause": "Clear one-paragraph explanation of what went wrong",
  "fixes": [
    {
      "type": "install|lint|test|docker",
      "title": "Short fix title",
      "description": "What to do",
      "code": "Exact code/command to fix it (if applicable)"
    }
  ],
  "prevention": "One sentence on how to prevent this in future",
  "confidence": "high|medium|low"
}"""


def read_logs() -> str:
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            content = f.read()
        if len(content) > 8000:
            content = "...[truncated]...\n" + content[-8000:]
        return content
    return "No log file found — pipeline may have failed before log collection."


# ── Secret Redaction Patterns ─────────────────────────────────────
# Each tuple: (compiled_regex, replacement_label)
_REDACTION_PATTERNS = [
    # ── Platform-specific tokens ──────────────────────────────────
    # GitHub personal access tokens (classic & fine-grained)
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "[REDACTED_GITHUB_TOKEN]"),
    # GitHub OAuth / App tokens
    (re.compile(r"gho_[A-Za-z0-9]{36,}"), "[REDACTED_GITHUB_OAUTH]"),
    # AWS Access Key IDs
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    # AWS Secret Access Keys (40 char base64-ish)
    (re.compile(r"(?<=[=:\s'\"])[A-Za-z0-9/+=]{40}(?=[\s'\"\n])"), "[REDACTED_AWS_SECRET]"),
    # Slack tokens  (xoxb-, xoxp-, xoxo-, xapp-)
    (re.compile(r"xox[bpoa]-[A-Za-z0-9\-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    # Anthropic API keys
    (re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"), "[REDACTED_ANTHROPIC_KEY]"),
    # OpenAI API keys
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED_OPENAI_KEY]"),
    # Google API keys (AIzaSy...)
    (re.compile(r"AIzaSy[A-Za-z0-9\-_]{33}"), "[REDACTED_GOOGLE_API_KEY]"),
    # npm tokens
    (re.compile(r"npm_[A-Za-z0-9]{36,}"), "[REDACTED_NPM_TOKEN]"),
    # Heroku API keys
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE), "[REDACTED_UUID_OR_HEROKU_KEY]"),

    # ── Generic credential patterns ───────────────────────────────
    # Bearer tokens in headers
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    # Basic auth header (base64 encoded user:pass)
    (re.compile(r"Basic\s+[A-Za-z0-9+/=]{10,}", re.IGNORECASE), "Basic [REDACTED_CREDENTIALS]"),
    # Authorization headers with generic tokens
    (re.compile(r"(Authorization:\s*)[^\n]+", re.IGNORECASE), r"\1[REDACTED_AUTH_HEADER]"),

    # ── Private key blocks ────────────────────────────────────────
    (re.compile(
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ), "[REDACTED_PRIVATE_KEY]"),

    # ── JWT tokens (header.payload.signature) ─────────────────────
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "[REDACTED_JWT]"),

    # ── Connection strings / DSNs ─────────────────────────────────
    # postgres://user:pass@host, mysql://user:pass@host, etc.
    (re.compile(r"(postgres|mysql|mongodb|redis|amqp|smtp)://[^\s]+", re.IGNORECASE), "[REDACTED_CONNECTION_STRING]"),

    # ── Generic key=value secrets ─────────────────────────────────
    # Catches patterns like: API_KEY=abc123..., secret="xyz...", token: 'abc...'
    (re.compile(
        r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|api[_-]?secret"
        r"|client[_-]?secret|password|passwd|db[_-]?password|database[_-]?url|token)"
        r"[\s]*[:=][\s]*['\"]?([A-Za-z0-9\-_./+=]{8,})['\"]?"
    ), r"\1=[REDACTED_SECRET]"),
]


def redact_secrets(logs: str) -> str:
    """Scrub sensitive values from pipeline logs before sending to AI.

    Applies a curated set of regex patterns that match common secret
    formats (API keys, tokens, passwords, private keys, JWTs,
    connection strings, etc.) and replaces them with safe placeholder
    labels.  This ensures no credentials are leaked to third-party
    AI providers during analysis.
    """
    redacted = logs
    redaction_count = 0
    for pattern, replacement in _REDACTION_PATTERNS:
        redacted, n = pattern.subn(replacement, redacted)
        redaction_count += n

    if redaction_count > 0:
        print(f"🔒 Redacted {redaction_count} potential secret(s) from logs.")
    else:
        print("🔒 No secrets detected in logs (redaction scan complete).")

    return redacted


def classify_failures(logs: str) -> dict:
    failures = []

    if "INSTALL_STATUS=failure" in logs:
        failures.append("install")
    if "LINT_STATUS=failure" in logs:
        failures.append("lint")
    if "TEST_STATUS=failure" in logs:
        failures.append("test")
    if "DOCKER_STATUS=failure" in logs:
        failures.append("docker")

    if not failures:
        lower = logs.lower()
        if "assertionerror" in lower or "pytest" in lower:
            failures.append("test")
        elif "modulenotfounderror" in lower or "no module named" in lower:
            failures.append("install")
        elif "syntaxerror" in lower:
            failures.append("lint")
        elif "docker build" in lower:
            failures.append("docker")
        else:
            failures.append("unknown")

    return {"detected": failures}


def parse_ai_response(raw_text: str) -> dict:
    text = raw_text.strip()
    # Strip markdown fences
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1] if len(parts) > 1 else text
        if text.startswith("json"):
            text = text[4:]
    text = text.strip()
    # Find JSON boundaries in case of extra text
    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        text = text[start:end]
    return json.loads(text)


def analyse_with_claude(logs: str, failure_context: dict) -> dict:
    try:
        from anthropic import Anthropic
    except ImportError:
        raise RuntimeError("anthropic package not installed. Run: pip install anthropic")

    if not ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable not set.")

    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    detected_types = ", ".join(failure_context["detected"]) or "unknown"
    print(f"🤖 Sending logs to Anthropic Claude (detected: {detected_types})...")

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Only analyze stages marked as failure. Do not treat section names like INSTALL LOGS, LINT LOGS, TEST LOGS, DOCKER LOGS as failures.\n\nFailed stages: {detected_types}\n\nLogs:\n{logs}\n\nRespond in JSON only."
        }]
    )
    return parse_ai_response(response.content[0].text)


def extract_failed_stage_logs(logs: str, failed_stages: list) -> str:
    stage_headers = {
        "install": "===== INSTALL LOGS =====",
        "lint":    "===== LINT LOGS =====",
        "test":    "===== TEST LOGS =====",
        "docker":  "===== DOCKER LOGS =====",
    }
    all_headers = list(stage_headers.values())
    extracted = []

    for stage in failed_stages:
        header = stage_headers.get(stage)
        if not header or header not in logs:
            continue
        start = logs.find(header)
        end = len(logs)
        for next_header in all_headers:
            pos = logs.find(next_header, start + len(header))
            if pos != -1:
                end = min(end, pos)
        extracted.append(logs[start:end].strip())

    return "\n\n".join(extracted) if extracted else logs


def analyse_with_gemini(logs: str, failure_context: dict) -> dict:
    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY environment variable not set.")

    detected_types = ", ".join(failure_context["detected"]) or "unknown"
    print(f"🤖 Sending logs to Google Gemini (detected: {detected_types})...")

    failed_logs = extract_failed_stage_logs(logs, failure_context["detected"])
    trimmed_logs = failed_logs[-8000:] if len(failed_logs) > 8000 else failed_logs

    combined_prompt = f"""You are a DevOps CI/CD failure analysis assistant.

Important rule:
Only analyze stages marked as failure. Do not treat section names like INSTALL LOGS, LINT LOGS, TEST LOGS, DOCKER LOGS as failures.
If a stage status is success, do not suggest fixes for it.

Detected failed stages: {detected_types}

Pipeline logs:
{trimmed_logs}

Respond with ONLY this JSON structure, no other text:
{{
  "severity": "high",
  "failure_types": {json.dumps(failure_context["detected"])},
  "root_cause": "one paragraph explanation",
  "fixes": [
    {{"type": "test", "title": "fix title", "description": "what to do", "code": "command if applicable"}}
  ],
  "prevention": "one sentence",
  "confidence": "high"
}}"""
  
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"

    payload = {
        "contents": [{"parts": [{"text": combined_prompt}]}],
        "generationConfig": {"temperature": 0.1, "maxOutputTokens": 8192}
    }

    response = requests.post(url, json=payload, timeout=60)
    response.raise_for_status()
    data = response.json()

    # Debug: print full raw response
    print(f"📨 Gemini raw response keys: {list(data.keys())}")
    candidate = data.get("candidates", [{}])[0]
    print(f"📨 Finish reason: {candidate.get('finishReason', 'unknown')}")
    raw_text = candidate.get("content", {}).get("parts", [{}])[0].get("text", "")
    print(f"📨 Raw response length: {len(raw_text)} chars")
    print(f"📨 Raw response preview: {raw_text[:500]}")

    return parse_ai_response(raw_text)


def analyse_with_ai(logs: str, failure_context: dict) -> dict:
    print(f"🔧 AI Provider: {AI_PROVIDER.upper()}")
    if AI_PROVIDER == "gemini":
        return analyse_with_gemini(logs, failure_context)
    elif AI_PROVIDER == "claude":
        return analyse_with_claude(logs, failure_context)
    else:
        raise ValueError(f"Unknown AI_PROVIDER: '{AI_PROVIDER}'. Use 'claude' or 'gemini'.")


def format_pr_comment(analysis: dict, commit_sha: str, run_id: str, repo: str) -> str:
    severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
        analysis.get("severity", "high"), "🟠")
    confidence_emoji = {"high": "✅", "medium": "⚠️", "low": "❓"}.get(
        analysis.get("confidence", "medium"), "⚠️")

    provider_label = "Anthropic Claude Sonnet" if AI_PROVIDER == "claude" else "Google Gemini 2.5 Flash"
    provider_badge = "🟣" if AI_PROVIDER == "claude" else "🔵"
    failure_types = analysis.get("failure_types", ["unknown"])
    if isinstance(failure_types, str):
        failure_types = [f.strip() for f in failure_types.split(",")]
    failure_badges = " ".join([f"`{ft}`" for ft in failure_types])

    fixes_md = ""
    for i, fix in enumerate(analysis.get("fixes", []), 1):
        fixes_md += f"\n#### Fix {i}: {fix.get('title', 'Suggested Fix')}\n"
        fixes_md += f"{fix.get('description', '')}\n"
        if fix.get("code"):
            fixes_md += f"\n```bash\n{fix['code']}\n```\n"

    run_url = f"https://github.com/{repo}/actions/runs/{run_id}"

    return f"""## 🤖 Self-Healing CI/CD Agent — Pipeline Analysis

> **Commit:** `{commit_sha[:8]}` | **Severity:** {severity_emoji} `{analysis.get('severity', 'unknown').upper()}` | **Confidence:** {confidence_emoji} `{analysis.get('confidence', 'medium')}` | **AI:** {provider_badge} `{provider_label}`

---

### 🔍 Failure Types Detected
{failure_badges}

---

### 🧠 Root Cause Analysis
{analysis.get('root_cause', 'Unable to determine root cause.')}

---

### 🛠️ Suggested Fixes
{fixes_md}

---

### 🛡️ Prevention
> {analysis.get('prevention', 'No prevention advice available.')}

---

<details>
<summary>📋 Pipeline Run Details</summary>

- **Run ID:** [{run_id}]({run_url})
- **Commit:** `{commit_sha}`
- **AI Provider:** {provider_label}
- **Configured via:** `AI_PROVIDER` environment variable

</details>

---
*🤖 Generated by [Self-Healing CI/CD Agent](https://github.com/{repo}). Supports Anthropic Claude & Google Gemini.*"""


def post_pr_comment(comment: str) -> bool:
    if not PR_NUMBER or PR_NUMBER == "None":
        print("⚠️  No PR number — direct push. Printing analysis:")
        print(comment)
        return False

    url = f"https://api.github.com/repos/{REPO_NAME}/issues/{PR_NUMBER}/comments"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    response = requests.post(url, headers=headers, json={"body": comment})

    if response.status_code == 201:
        print(f"✅ Analysis posted to PR #{PR_NUMBER}")
        return True
    else:
        print(f"❌ Failed to post comment: {response.status_code} — {response.text}")
        return False


def main():
    print("🚀 Self-Healing CI/CD Agent starting...")
    print(f"   Repo:     {REPO_NAME}")
    print(f"   PR:       #{PR_NUMBER}")
    print(f"   SHA:      {COMMIT_SHA[:8] if COMMIT_SHA else 'unknown'}")
    print(f"   Provider: {AI_PROVIDER.upper()}")

    if AI_PROVIDER == "claude" and not ANTHROPIC_API_KEY:
        print("❌ AI_PROVIDER=claude but ANTHROPIC_API_KEY not set.")
        sys.exit(1)
    if AI_PROVIDER == "gemini" and not GEMINI_API_KEY:
        print("❌ AI_PROVIDER=gemini but GEMINI_API_KEY not set.")
        sys.exit(1)

    logs = read_logs()
    print(f"📄 Logs loaded ({len(logs)} characters)")

    # ── Security: scrub secrets before any downstream processing ──
    logs = redact_secrets(logs)
    print(f"🔒 Logs sanitised ({len(logs)} characters after redaction)")

    failure_context = classify_failures(logs)
    print(f"🔍 Detected failures: {failure_context['detected']}")

    if not failure_context["detected"] or failure_context["detected"] == ["unknown"]:
        print("✅ No failures detected — pipeline healthy.")
        if PR_NUMBER and PR_NUMBER != "None":
            post_pr_comment("## 🤖 Self-Healing CI/CD Agent\n\n✅ **No failures detected.** All checks passed!\n")
        return

    try:
        analysis = analyse_with_ai(logs, failure_context)
        print(f"🧠 Analysis complete. Severity: {analysis.get('severity', 'unknown')}")
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse AI response as JSON: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ AI provider error: {e}")
        sys.exit(1)

    comment = format_pr_comment(analysis, COMMIT_SHA, RUN_ID, REPO_NAME)
    post_pr_comment(comment)

    with open("agent-analysis.json", "w") as f:
        json.dump(analysis, f, indent=2)
    print("💾 Saved to agent-analysis.json")
    print("✅ Agent completed.")


if __name__ == "__main__":
    main()
