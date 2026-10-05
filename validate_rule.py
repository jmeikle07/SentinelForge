"""
validate_rule.py - SentinelForge autonomous rule engine: self-healing validation pipeline

Stages:
  1. YAML lint - catch malformed YAML before burning API calls
  2. Sigma -> Lucene conversion
  3. Backtest - verify query matches real data in Elasticsearch (7-day window)
  4. 3-AI validation - Claude + Gemini + Ollama score the rule (run concurrently)
  5. Self-heal - Claude rewrites failing rules using structured feedback
  6. Circuit breaker - email alert after 3 failed attempts

Max 3 attempts. Healed rule written back to file for git commit.
An unreachable Elasticsearch is a FAILED backtest (never a silent pass).
"""

import concurrent.futures
import html as html_lib
import json
import logging
import os
import re
import smtplib
import ssl
import sys
import time
import yaml
import requests
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from string import Template

from lab import ecs
from lab import config as lab_config
from lab import state as lab_state
from lab.http import session as make_session

log = logging.getLogger("sf.validate")

HERE = Path(__file__).resolve().parent
MODEL_DEFAULT = "claude-sonnet-4-6"
BACKTEST_WINDOW = "now-7d"
MAX_ATTEMPTS = 3


class MissingApiKey(RuntimeError):
    """A validator's API key is not configured; that voter is skipped."""


def model_name():
    return os.environ.get("MODEL_NAME") or MODEL_DEFAULT


# -- Sigma conversion (single shared copy lives in lab.ecs) --------------------

def convert_sigma(rule_path):
    """Convert a Sigma YAML file to a Lucene query string (ECS field names)."""
    result = ecs.convert_path(rule_path)
    return result[0] if result else None


def convert_sigma_text(rule_text):
    """Convert Sigma YAML text (not a file) to a Lucene query string."""
    result = ecs.convert(rule_text)
    return result[0] if result else None


# -- Stage 1: YAML lint --------------------------------------------------------

def lint_sigma_yaml(rule_text):
    """Check YAML syntax and required Sigma fields before burning API calls."""
    try:
        parsed   = yaml.safe_load(rule_text)
    except yaml.YAMLError as e:
        return False, f"YAML syntax error: {e}"
    if not isinstance(parsed, dict):
        return False, "Rule is not a YAML mapping"
    required = ["title", "id", "logsource", "detection"]
    missing  = [f for f in required if f not in parsed]
    if missing:
        return False, f"Missing required fields: {missing}"
    return True, "OK"


# -- Stage 3: Backtest ---------------------------------------------------------

def backtest_query(query):
    """
    Run the Lucene query against logs-* over the last 7 days and count matches.
    Returns (hit_count, error_message). error_message is set when Elasticsearch is
    unconfigured, unreachable or errors; callers must treat that as a FAILED backtest.
    A count of 0 with no error means field names are wrong or the logic is unreachable.
    """
    try:
        settings = lab_config.load()
    except lab_config.ConfigError as e:
        return 0, f"Backtest not configured: {e}"

    headers = {"Content-Type": "application/json"}
    if settings.elastic_api_key:
        headers["Authorization"] = f"ApiKey {settings.elastic_api_key}"
    body = {"query": {"bool": {
        "must": [{"query_string": {"query": query, "analyze_wildcard": True}}],
        "filter": [{"range": {"@timestamp": {"gte": BACKTEST_WINDOW}}}],
    }}}
    try:
        resp = make_session(timeout=15).post(
            f"{settings.elastic_url}/logs-*/_count", headers=headers, json=body)
    except requests.RequestException as e:
        return 0, f"Backtest connection error: {e}"
    if resp.status_code != 200:
        return 0, f"Elasticsearch returned {resp.status_code}: {resp.text[:200]}"
    try:
        return int(resp.json().get("count", 0)), None
    except (ValueError, AttributeError) as e:
        return 0, f"Backtest returned an unreadable response: {e}"


def passes(approvals, avg_score, hit_count, backtest_err):
    """Pass condition: 2+ approvals, avg >= 6, and a SUCCESSFUL backtest with > 0 hits."""
    return approvals >= 2 and avg_score >= 6 and backtest_err is None and hit_count > 0


# -- Stage 4: AI validators ----------------------------------------------------

VALIDATION_PROMPT = Template("""You are a detection engineering expert reviewing a Sigma rule for a home detection lab.

Score this rule 1-10 using these exact criteria:
- 8-10: Valid logsource, correct ECS fields, logical detection condition, ATT&CK tags present, would realistically fire on attacker behavior
- 5-7: Minor issues like slightly broad conditions or missing optional fields, but functionally sound
- 1-4: Wrong field names, impossible logic, would never fire, or is dangerously noisy with no filters

This is a lab environment with Sysmon + Elastic Agent on Windows. Be practical, not academic.
A score of 6+ with approve=true means deploy it. Do not fail rules for being imperfect — fail them only if they are fundamentally broken.

Rule:
$rule_text

Elastic Query:
$query

Respond with JSON only: {"score": 1-10, "approve": true/false, "issues": [], "reasoning": ""}""")


def build_validation_prompt(rule_text, query):
    # Template (not str.format): rule text and queries may contain braces freely.
    return VALIDATION_PROMPT.substitute(rule_text=rule_text, query=query)


def parse_llm_response(text):
    try:
        clean = text.replace("```json", "").replace("```", "").strip()
        parsed = json.loads(clean)
        if isinstance(parsed, dict):
            return parsed
    except (ValueError, AttributeError):
        pass
    return {"score": 5, "approve": False, "issues": ["Could not parse response"], "reasoning": str(text)[:200]}


def ask_ollama(rule_text, query):
    prompt = build_validation_prompt(rule_text, query)
    base = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    response = make_session(timeout=120).post(
        f"{base}/api/generate",
        json={"model": os.environ.get("OLLAMA_MODEL", "qwen2.5:14b"), "prompt": prompt, "stream": False},
    )
    response.raise_for_status()
    return parse_llm_response(response.json().get("response", ""))


def ask_claude(rule_text, query):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise MissingApiKey("ANTHROPIC_API_KEY is not set")
    prompt = build_validation_prompt(rule_text, query)
    response = make_session(timeout=60).post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model_name(),
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        },
    )
    response.raise_for_status()
    return parse_llm_response(response.json()["content"][0]["text"])


def ask_gemini(rule_text, query):
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise MissingApiKey("GEMINI_API_KEY is not set")
    prompt = build_validation_prompt(rule_text, query)
    response = make_session(timeout=60).post(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
        headers={"x-goog-api-key": key},
        json={"contents": [{"parts": [{"text": prompt}]}]},
    )
    resp = response.json()
    if "candidates" not in resp:
        return {"score": 5, "approve": False, "issues": ["Gemini API error"], "reasoning": str(resp)[:200]}
    return parse_llm_response(resp["candidates"][0]["content"]["parts"][0]["text"])


def validate_rule_text(rule_text, query):
    """Run the 3 validators concurrently. Returns approvals, avg_score, feedback_by_validator.

    A voter whose API key is missing is skipped with a warning (not counted). A voter that
    errors is logged and counted as a rejection with score 0."""
    voters = {"Ollama": ask_ollama, "Claude": ask_claude, "Gemini": ask_gemini}
    feedback = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(voters)) as pool:
        futures = {pool.submit(fn, rule_text, query): name for name, fn in voters.items()}
        results = {}
        for fut in concurrent.futures.as_completed(futures):
            name = futures[fut]
            try:
                results[name] = fut.result()
            except MissingApiKey as e:
                log.warning("skipping %s validator: %s", name, e)
            except (requests.RequestException, KeyError, IndexError, ValueError) as e:
                log.error("%s validator failed: %s", name, e)
                results[name] = {"score": 0, "approve": False,
                                 "issues": [f"validator error: {e}"], "reasoning": str(e)[:200]}
    for name in voters:  # stable order
        if name in results:
            feedback[name] = results[name]
            print(f"  {name}:  score={results[name].get('score')} approve={results[name].get('approve')}")

    approvals = sum(bool(r.get("approve", False)) for r in feedback.values())
    avg_score = (sum(r.get("score", 0) for r in feedback.values()) / len(feedback)) if feedback else 0.0

    print(f"  Results: {approvals}/{len(feedback)} approved - avg score {avg_score:.1f}/10")
    return approvals, avg_score, feedback


# ── Stage 5: Self-healer ──────────────────────────────────────────────────────

HEAL_PROMPT = Template("""You are a detection engineering expert. This Sigma rule failed validation on attempt $attempt.

ORIGINAL RULE:
$rule_text

ELASTIC QUERY IT PRODUCED:
$query

BACKTEST RESULT:
$backtest_info

STRUCTURED VALIDATOR FEEDBACK:
$feedback

REFERENCE — A GOOD SIGMA RULE (use this as a template for structure and field names):
title: PowerShell Encoded Command Execution
id: a2b1c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects PowerShell execution with encoded command argument, commonly used to obfuscate malicious code.
author: Example Author
date: 2026/05/10
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process.name: powershell.exe
        process.command_line|contains:
            - '-EncodedCommand'
            - '-enc '
            - '-ec '
    condition: selection
falsepositives:
    - Legitimate administrative scripts using encoded commands
level: medium
fields:
    - process.name
    - process.command_line
    - process.parent.name

RULES FOR YOUR REWRITE:
1. Valid ECS fields ONLY: process.name, process.executable, process.command_line,
   process.parent.name, process.parent.executable, registry.key, registry.value,
   network.destination.ip, file.path, file.name, event.code, user.name, host.name
2. BANNED modifiers — NEVER use: |in, |lowercasefield, |re — not supported by pySigma 0.11.23. Use contains, startswith, endswith, or exact match instead
3. Simple, single selection block — one clear detection condition
4. Keep the same ATT&CK technique ID in tags
5. Keep the same rule id (UUID)
6. If the backtest showed 0 hits, simplify the detection to match more broadly

Return ONLY the complete fixed Sigma YAML. No explanation. No markdown fences.""")


def build_heal_prompt(rule_text, query, backtest_info, feedback, attempt):
    return HEAL_PROMPT.substitute(attempt=attempt, rule_text=rule_text, query=query,
                                  backtest_info=backtest_info, feedback=feedback)


def heal_rule(rule_text, query, backtest_count, feedback_by_validator, attempt):
    """Ask Claude to rewrite a failing rule using structured per-validator feedback."""
    structured = ""
    for validator, result in feedback_by_validator.items():
        structured += f"\n{validator} (score {result.get('score')}/10, approve={result.get('approve')}):\n"
        for issue in result.get("issues", []):
            structured += f"  - {issue}\n"
        if result.get("reasoning"):
            structured += f"  reasoning: {result.get('reasoning')[:300]}\n"

    backtest_info = (
        f"Query returned {backtest_count} hits against logs-* - field names appear valid"
        if backtest_count > 0
        else "Query returned 0 hits against logs-* (or the backtest could not run) - field names are likely wrong or logic is unreachable"
    )

    prompt = build_heal_prompt(rule_text, query, backtest_info, structured, attempt)

    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise MissingApiKey("ANTHROPIC_API_KEY is not set; cannot self-heal")
    response = make_session(timeout=90).post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model_name(),
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
        },
    )
    response.raise_for_status()
    healed = response.json()["content"][0]["text"].strip()
    return healed.replace("```yaml", "").replace("```", "").strip()


# ── Circuit breaker email ─────────────────────────────────────────────────────

def send_circuit_breaker_email(rule_path, attempts, feedback_history):
    """Email when self-healing gives up - HTML design matching the autonomous rule engine emails."""
    smtp_host = os.environ.get("SMTP_HOST", "")
    smtp_port = int(os.environ.get("SMTP_PORT", "587") or 587)
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASSWORD", "")
    mail_from = os.environ.get("SMTP_FROM", "") or smtp_user
    mail_to   = os.environ.get("SMTP_TO", "")
    if not all([smtp_host, mail_from, mail_to]):
        print("  [circuit breaker] email credentials not set — skipping notification")
        return

    now       = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    rule_name = rule_path.split("/")[-1].replace(".yml", "").replace("-", " ").title()

    BG    = "#0d1117"
    CARD  = "#161b22"
    BORD  = "#21262d"
    TEXT  = "#e6edf3"
    MUTED = "#8b949e"
    RED   = "#f85149"

    feedback_rows = ""
    for i, fb in enumerate(feedback_history, 1):
        feedback_rows += f"""<tr><td colspan="4" style="padding:8px 14px 2px;font-size:11px;font-weight:700;letter-spacing:1px;color:{MUTED};text-transform:uppercase;background:{CARD};">Attempt {i}</td></tr>"""
        for validator, result in fb.items():
            score     = result.get("score", "?")
            approved  = result.get("approve", False)
            reasoning = (result.get("reasoning") or "")[:180]
            a_color   = "#4caf50" if approved else RED
            a_label   = "APPROVED" if approved else "REJECTED"
            s_color   = "#4caf50" if (isinstance(score, int) and score >= 7) else "#ff9800" if (isinstance(score, int) and score >= 5) else RED
            feedback_rows += f"""<tr style="border-bottom:1px solid {BORD};"><td style="padding:8px 14px;font-size:13px;color:{TEXT};font-weight:600;">{validator}</td><td style="padding:8px 14px;text-align:center;"><span style="background:{s_color}22;color:{s_color};border:1px solid {s_color}55;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;font-family:monospace;">{score}/10</span></td><td style="padding:8px 14px;text-align:center;"><span style="background:{a_color}22;color:{a_color};border:1px solid {a_color}55;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;font-family:monospace;">{a_label}</span></td><td style="padding:8px 14px;font-size:12px;color:{MUTED};font-style:italic;">{reasoning}</td></tr>"""

    repo_url = os.environ.get("SF_REPO_URL", "").rstrip("/")
    rule_link = ""
    if repo_url:
        rule_link = (f'<table cellpadding="0" cellspacing="0"><tr><td><a href="{html_lib.escape(repo_url)}/blob/main/{html_lib.escape(rule_path)}" '
                     f'style="display:inline-block;background:{RED};color:#ffffff;text-decoration:none;padding:10px 20px;'
                     f'border-radius:6px;font-size:13px;font-weight:700;">View Rule on GitHub</a></td></tr></table>')

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>SentinelForge</title></head>
<body style="margin:0;padding:0;background:{BG};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:{BG};"><tr><td align="center" style="padding:32px 16px;">
<table width="580" cellpadding="0" cellspacing="0" style="background:{CARD};border-radius:10px;border:1px solid {BORD};overflow:hidden;">
<tr><td style="padding:22px 36px 16px;border-bottom:1px solid {BORD};"><p style="margin:0;font-size:10px;font-weight:600;letter-spacing:2px;color:{MUTED};text-transform:uppercase;">SentinelForge Detection Lab</p></td></tr>
<tr><td style="padding:20px 36px;"><p style="margin:0;font-size:13px;color:{MUTED};">{now}</p><h1 style="margin:6px 0 0;font-size:20px;font-weight:700;color:{TEXT};">Circuit Breaker Fired</h1></td></tr>
<tr><td style="padding:0 36px 20px;"><p style="margin:0;font-size:14px;color:{TEXT};line-height:1.7;padding:14px 16px;background:{BG};border-left:3px solid {RED};border-radius:0 6px 6px 0;">The self-healing pipeline tried to fix this rule <strong>{attempts} times</strong> and failed every attempt. Manual review or deletion required.</p></td></tr>
<tr><td style="padding:0 36px 20px;">
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid {BORD};border-radius:6px;overflow:hidden;background:{BG};"><tr>
    <td style="padding:12px 8px;border-right:1px solid {BORD};text-align:center;"><p style="margin:0 0 4px;font-size:9px;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Rule</p><p style="margin:0;font-size:11px;font-weight:700;color:{RED};font-family:monospace;">{rule_name}</p></td>
    <td style="padding:12px 8px;border-right:1px solid {BORD};text-align:center;"><p style="margin:0 0 4px;font-size:9px;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Attempts</p><p style="margin:0;font-size:20px;font-weight:700;color:{RED};">{attempts}</p></td>
    <td style="padding:12px 8px;text-align:center;"><p style="margin:0 0 4px;font-size:9px;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Status</p><p style="margin:0;font-size:11px;font-weight:700;color:{RED};font-family:monospace;">FAILED</p></td>
  </tr></table>
</td></tr>
<tr><td style="padding:0 36px 20px;">
  <p style="margin:0 0 10px;font-size:10px;font-weight:600;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Validator Feedback</p>
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid {BORD};border-radius:6px;overflow:hidden;background:{BG};">
  <tr style="background:{CARD};"><td style="padding:8px 14px;font-size:10px;font-weight:700;letter-spacing:1px;color:{MUTED};text-transform:uppercase;">Validator</td><td style="padding:8px 14px;font-size:10px;font-weight:700;letter-spacing:1px;color:{MUTED};text-transform:uppercase;text-align:center;">Score</td><td style="padding:8px 14px;font-size:10px;font-weight:700;letter-spacing:1px;color:{MUTED};text-transform:uppercase;text-align:center;">Result</td><td style="padding:8px 14px;font-size:10px;font-weight:700;letter-spacing:1px;color:{MUTED};text-transform:uppercase;">Reasoning</td></tr>
  {feedback_rows}
  </table>
</td></tr>
<tr><td style="padding:0 36px 28px;">
  <p style="margin:0 0 10px;font-size:10px;font-weight:600;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Action Required</p>
  <p style="margin:0;font-size:14px;color:{TEXT};line-height:1.7;padding:14px 16px;background:{BG};border:1px solid {BORD};border-radius:6px;">Delete <code style="font-family:monospace;background:{CARD};padding:2px 6px;border-radius:3px;color:{RED};">{rule_path}</code> and let the SentinelForge rule engine regenerate, or manually fix the Sigma YAML.</p>
  <br>
  {rule_link}
</td></tr>
</table></td></tr></table></body></html>"""

    msg = EmailMessage()
    msg["Subject"] = f"[Circuit Breaker] {rule_name} — failed after {attempts} attempts"
    msg["From"]    = mail_from
    msg["To"]      = mail_to
    msg.set_content(f"Circuit breaker fired on {rule_path} after {attempts} attempts.")
    msg.add_alternative(html, subtype="html")

    try:
        ctx = ssl.create_default_context()
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx, timeout=30)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
        with server as s:
            if smtp_port != 465:
                s.starttls(context=ctx)
            if smtp_user:
                s.login(smtp_user, smtp_pass)
            s.send_message(msg)
        print(f"  [circuit breaker] email sent to {mail_to}")
    except (smtplib.SMTPException, OSError) as e:
        log.error("circuit breaker email failed: %s", e)


_ID_RE = re.compile(r"^id:\s*(.+)$", re.MULTILINE)
_TITLE_RE = re.compile(r"^title:\s*(.+)$", re.MULTILINE)


def save_validation(rule_path, rule_text, feedback_history, approvals, avg_score, attempt, backtest_hits, outcome):
    """Persist the real 3-AI vote receipts so the dashboard can show them (no invented data)."""
    vfile = HERE / "state" / "rule_validations.json"
    m, mt = _ID_RE.search(rule_text), _TITLE_RE.search(rule_text)
    rid = m.group(1).strip() if m else os.path.basename(rule_path)
    title = mt.group(1).strip() if mt else None
    vfile.parent.mkdir(parents=True, exist_ok=True)
    data = lab_state.read(vfile, default={})  # StateCorrupt propagates: never overwrite a corrupt file
    attempts = []
    for i, fb in enumerate(feedback_history, 1):
        votes = {v: {"score": r.get("score"), "approve": r.get("approve")} for v, r in fb.items()}
        attempts.append({"attempt": i, "votes": votes})
    data[rid] = {
        "title": title,
        "rule_file": os.path.basename(rule_path),
        "outcome": outcome,                 # "approved" or "failed"
        "final_attempt": attempt,
        "approvals": approvals,             # final approvals
        "avg_score": round(avg_score, 1),
        "backtest_hits": backtest_hits,
        "attempts": attempts,
        "validated_at": datetime.now(timezone.utc).isoformat(),
    }
    lab_state.write(vfile, data)


def _safe_heal(rule_text, query, hits, feedback, attempt):
    """heal_rule that never raises: a failed heal keeps the current text for the next attempt."""
    try:
        return heal_rule(rule_text, query, hits, feedback, attempt)
    except (MissingApiKey, requests.RequestException, KeyError, IndexError, ValueError) as e:
        log.error("self-heal failed: %s", e)
        return None


def main():
    logging.basicConfig(level="INFO", format="%(message)s")
    rule_path = sys.argv[1]

    with open(rule_path, "r", encoding="utf-8") as f:
        original_rule_text = f.read()

    rule_text        = original_rule_text
    feedback_history = []
    last_backtest    = 0

    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"\n{'='*52}")
        print(f"  Attempt {attempt}/{MAX_ATTEMPTS}: {rule_path}")
        print(f"{'='*52}")

        # Stage 1: YAML lint
        print("  Stage 1: YAML lint...")
        valid, lint_msg = lint_sigma_yaml(rule_text)
        if not valid:
            print(f"  YAML lint FAILED: {lint_msg}")
            if attempt < MAX_ATTEMPTS:
                print("  Sending to Claude for structural repair...")
                time.sleep(2)
                rule_text = _safe_heal(
                    rule_text, "N/A — YAML invalid", 0,
                    {"lint": {"score": 0, "approve": False,
                              "issues": [lint_msg], "reasoning": lint_msg}},
                    attempt
                ) or rule_text
                continue
            else:
                send_circuit_breaker_email(rule_path, attempt, feedback_history)
                print(f"FAIL: Rule could not be fixed after {MAX_ATTEMPTS} attempts")
                sys.exit(1)
        print("  YAML lint OK")

        # Stage 2: Convert to Lucene
        print("  Stage 2: Converting to Lucene query...")
        try:
            if rule_text == original_rule_text:
                query = convert_sigma(rule_path)
            else:
                query = convert_sigma_text(rule_text)
        except Exception as e:  # pySigma raises many distinct error types
            log.error("Sigma conversion error: %s", e)
            query = None

        if not query:
            print("  Conversion FAILED: pySigma could not convert this rule")
            if attempt < MAX_ATTEMPTS:
                time.sleep(2)
                rule_text = _safe_heal(
                    rule_text, "N/A — conversion failed", 0,
                    {"converter": {"score": 0, "approve": False,
                                   "issues": ["pySigma could not convert this rule"],
                                   "reasoning": "Rule could not be converted to Lucene query"}},
                    attempt
                ) or rule_text
                continue
            else:
                send_circuit_breaker_email(rule_path, attempt, feedback_history)
                sys.exit(1)

        print(f"  Query: {query[:120]}{'...' if len(query) > 120 else ''}")

        # Stage 3: Backtest against Elasticsearch
        print("  Stage 3: Backtesting against logs-* (7d)...")
        hit_count, backtest_err = backtest_query(query)
        last_backtest = hit_count

        if backtest_err:
            print(f"  Backtest FAILED: {backtest_err}")
        elif hit_count == 0:
            print("  Backtest: 0 hits — field names may be wrong")
        else:
            print(f"  Backtest: {hit_count} hits — query matches real data ✓")

        # Stage 4: 3-AI validation
        print("  Stage 4: AI validation...")
        approvals, avg_score, feedback = validate_rule_text(rule_text, query)
        feedback_history.append(feedback)

        # Pass condition: 2 approvals + avg >= 6 + a successful backtest with > 0 hits
        if passes(approvals, avg_score, hit_count, backtest_err):
            # Write healed rule back if it changed
            if rule_text != original_rule_text:
                with open(rule_path, "w", encoding="utf-8") as f:
                    f.write(rule_text)
                print(f"  Self-healed rule written back to {rule_path}")
            save_validation(rule_path, rule_text, feedback_history, approvals, avg_score, attempt, last_backtest, "approved")
            print(f"\nPASS: Rule approved on attempt {attempt} ✓")
            sys.exit(0)

        # Build failure reason
        reasons = []
        if approvals < 2:
            reasons.append(f"only {approvals}/3 validators approved")
        if avg_score < 6:
            reasons.append(f"avg score {avg_score:.1f} < 6")
        if backtest_err:
            reasons.append(f"backtest failed: {backtest_err}")
        elif hit_count == 0:
            reasons.append("0 backtest hits — fields likely wrong")
        print(f"  Failed: {', '.join(reasons)}")

        if attempt < MAX_ATTEMPTS:
            print(f"\n  Attempt {attempt} failed — Claude is rewriting the rule...")
            time.sleep(3)
            healed = _safe_heal(rule_text, query, hit_count, feedback, attempt)
            if healed and len(healed) > 100:
                rule_text = healed
                print("  Rule rewritten — retrying...\n")
            else:
                print("  Healing returned empty result — keeping rule for next attempt")
        else:
            print(f"\nCIRCUIT BREAKER: Rule failed after {MAX_ATTEMPTS} attempts")
            send_circuit_breaker_email(rule_path, MAX_ATTEMPTS, feedback_history)
            save_validation(rule_path, rule_text, feedback_history, approvals, avg_score, attempt, last_backtest, "failed")
            print("FAIL: Rule could not be self-healed — manual review required")
            sys.exit(1)


if __name__ == "__main__":
    main()
