"""
SentinelForge Hunt - web API.
Thin wrapper over sf_hunt. Imports the real logic, never duplicates it.
Serves the concise verdict + source breakdown as JSON, and the static page.

Security model:
  - State-changing routes (/api/approve, /api/reject) require the LAB_ADMIN_TOKEN value in the
    X-Admin-Token header (constant-time compare). With no token configured they are disabled.
  - rule_id path parameters must be UUIDs (no path traversal into the filesystem or subprocess).
  - /api/hunt is rate limited per client address.
"""
import hmac
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import sf_hunt as tk
from lab import coverage
from lab import state as lab_state

log = logging.getLogger(__name__)

app = FastAPI(title="SentinelForge Hunt")

HERE = Path(__file__).resolve().parent
WEB_DIR = HERE / "web"

# Per-client sliding-window limit for /api/hunt (each call fans out to paid/quota'd intel APIs).
HUNT_RATE_LIMIT = int(os.environ.get("SF_HUNT_RATE_LIMIT", "10"))      # requests ...
HUNT_RATE_WINDOW = float(os.environ.get("SF_HUNT_RATE_WINDOW", "60"))  # ... per this many seconds
_rate_hits: dict = defaultdict(deque)
_rate_lock = threading.Lock()

APPROVE_TIMEOUT_SECONDS = 120


def _reset_rate_limits() -> None:
    with _rate_lock:
        _rate_hits.clear()


def _check_rate_limit(request: Request) -> None:
    """Raise 429 when this client exceeded HUNT_RATE_LIMIT calls in the window.
    Keyed on the socket peer address: behind a reverse proxy that is the proxy, so run the
    proxy's own per-client limiter in that setup (X-Forwarded-For is client-controlled)."""
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _rate_lock:
        hits = _rate_hits[client]
        while hits and now - hits[0] >= HUNT_RATE_WINDOW:
            hits.popleft()
        if len(hits) >= HUNT_RATE_LIMIT:
            retry = max(1, int(HUNT_RATE_WINDOW - (now - hits[0])) + 1)
            raise HTTPException(status_code=429, detail="rate limit exceeded",
                                headers={"Retry-After": str(retry)})
        hits.append(now)


def _state(name: str, default):
    """Read a JSON state file. Missing -> default. Corrupt -> logged (file quarantined by
    lab.state) and default. Never silently swallowed."""
    try:
        return lab_state.read(HERE / "state" / name, default=default)
    except lab_state.StateCorrupt as exc:
        log.error("state file %s is corrupt: %s", name, exc)
    except OSError as exc:
        log.error("cannot read state file %s: %s", name, exc)
    return default


def _require_rule_id(rule_id: str) -> str:
    """Rule ids are UUIDs. Anything else (including '../x') is a 400. Returns canonical form."""
    try:
        return str(uuid.UUID(rule_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=400, detail="rule_id must be a UUID")


def _run_hunt(ioc: str) -> dict:
    ioc = (ioc or "").strip()
    if not ioc:
        raise HTTPException(status_code=400, detail="empty IOC")
    ioc_type = tk.detect_ioc_type(ioc)
    if ioc_type not in ("ipv4", "md5", "sha1", "sha256", "domain"):
        return {"ioc": ioc, "ioc_type": ioc_type, "supported": False,
                "message": f"Unsupported IOC type: {ioc_type}. Supported: IPv4, file hash, domain."}

    conn = tk.memory_init()
    try:
        is_hash = ioc_type in ("md5", "sha1", "sha256")
        is_domain = ioc_type == "domain"
        if is_hash:
            external = tk.bucket_external_hash(conn, ioc, ioc_type)
        elif is_domain:
            external = tk.bucket_external_domain(conn, ioc)
        else:
            # External IP sources only (no internal SIEM/T-Pot on this route); a failure here
            # leaves external empty, which yields an INSUFFICIENT DATA verdict, never a benign one.
            try:
                external = tk.bucket_external_ip(conn, ioc)
            except Exception as e:  # noqa: BLE001 - degrade gracefully, but never silently
                log.warning("external IP enrichment for %s failed: %r", ioc, e)
                external = {}
        # No T-Pot data on the web route: bucket_verdict renormalises over the sources that
        # actually answered, so the same inputs give the same verdict as the CLI (which passes
        # real observed data; an empty/errored one carries no weight).
        verdict = tk.bucket_verdict({}, external, ioc_type)
    finally:
        conn.close()

    return {"ioc": ioc, "ioc_type": ioc_type, "supported": True,
            "verdict": verdict, "external": external}


@app.get("/api/hunt")
def api_hunt(ioc: str, request: Request):
    _check_rate_limit(request)
    return JSONResponse(_run_hunt(ioc))


# ── Engine dashboard data ──────────────────────────────────────────────────────
# Reads the rule engine's real state files. No invented data.
TACTIC_ORDER = list(coverage.TACTICS)


@app.get("/api/engine")
def api_engine():
    seen = _state("seen_techniques.json", {})
    hunt_log = _state("hunt_log.json", [])
    last_run_doc = _state("last_run.json", {})
    last_run = last_run_doc.get("timestamp") if isinstance(last_run_doc, dict) else None
    # rule efficacy snapshot (real fires per deployed rule; updated when rule_efficacy.py runs)
    efficacy = None
    eff = _state("rule_efficacy.json", None)
    if isinstance(eff, dict):
        fired = []
        for tid, r in (eff.get("by_technique") or {}).items():
            if isinstance(r, dict) and r.get("fire_count", 0) > 0:
                fired.append({
                    "id": tid,
                    "name": r.get("technique_name"),
                    "count": r.get("fire_count", 0),
                    "last_fired": r.get("last_fired"),
                })
        fired.sort(key=lambda x: x["count"], reverse=True)
        efficacy = {
            "measured_at": eff.get("generated_at"),
            "total_rules": eff.get("total_rules", 0),
            "rules_fired": eff.get("rules_fired", 0),
            "rules_dormant": eff.get("rules_dormant", 0),
            "fired": fired,
        }
    # 3-AI validation receipts (real per-validator votes, from validate_rule.py)
    validations = None
    vraw = _state("rule_validations.json", None)
    if isinstance(vraw, dict):
        items = []
        for rid, v in vraw.items():
            atts = v.get("attempts") or []
            items.append({
                "title": v.get("title"),
                "outcome": v.get("outcome"),
                "final_attempt": v.get("final_attempt"),
                "avg_score": v.get("avg_score"),
                "backtest_hits": v.get("backtest_hits"),
                "validated_at": v.get("validated_at"),
                "attempts": atts,
                "healed": len(atts) > 1,
            })
        items.sort(key=lambda x: x.get("validated_at") or "", reverse=True)
        validations = items[:6]

    # techniques grouped by tactic: coverage is what the shipped rules tag (lab.coverage),
    # state only adds names / confidence / deploy time where it has them
    try:
        covered = coverage.covered(HERE / "detections" / "sigma", seen)
    except coverage.CoverageError as exc:
        log.error("coverage unavailable: %s", exc)
        raise HTTPException(status_code=500, detail="coverage unavailable: a rule file is unreadable")
    by_tactic = {}
    for tid, t in covered.items():
        for tac in (t["tactics"] or ["unknown"]):
            by_tactic.setdefault(tac, []).append({
                "id": tid,
                "name": t.get("technique_name"),
                "confidence": t.get("confidence"),
                "deployed_at": t.get("deployed_at"),
            })
    for tac in by_tactic:
        by_tactic[tac].sort(key=lambda x: x["id"])

    # outcome + confidence counts from the log
    outcomes, confidences = {}, {}
    for e in hunt_log:
        outcomes[e.get("result", "unknown")] = outcomes.get(e.get("result", "unknown"), 0) + 1
        c = e.get("confidence")
        if c:
            confidences[c] = confidences.get(c, 0) + 1

    # count rule files actually on disk
    sigma_dir = HERE / "detections" / "sigma"
    prod_rules = len(list(sigma_dir.glob("*.yml"))) if sigma_dir.exists() else 0
    ht_dir = sigma_dir / "hunt-triggered"
    hunt_triggered = len(list(ht_dir.glob("*.yml"))) if ht_dir.exists() else 0

    # newest-first timeline (cap to 60)
    timeline = sorted(hunt_log, key=lambda e: e.get("timestamp") or "", reverse=True)[:60]

    return JSONResponse({
        "last_run": last_run,
        "techniques_covered": len(covered),
        "tactic_order": TACTIC_ORDER,
        "by_tactic": by_tactic,
        "outcomes": outcomes,
        "confidences": confidences,
        "prod_rules": prod_rules,
        "hunt_triggered": hunt_triggered,
        "timeline": timeline,
        "efficacy": efficacy,
        "validations": validations,
    })


def _require_admin(token: str = None) -> None:
    """These endpoints CHANGE state (deploy rules). Require the LAB_ADMIN_TOKEN value in the
    X-Admin-Token header. Works behind a reverse proxy (unlike a client-address check, which
    sees only the proxy). With LAB_ADMIN_TOKEN unset the routes are disabled (fail closed)."""
    expected = os.environ.get("LAB_ADMIN_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=403, detail="approvals disabled: LAB_ADMIN_TOKEN is not set")
    if not token or not hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="missing or invalid admin token")


@app.get("/api/pending")
def api_pending():
    """List rules waiting for human approval, with their 3-AI vote receipts."""
    pending = _state("pending_rules.json", [])
    validations = _state("rule_validations.json", {})
    # attach the vote receipt (by rule_id) to each pending rule if we have it
    out = []
    for p in pending:
        rec = validations.get(p.get("rule_id"))
        out.append({
            "rule_id": p.get("rule_id"),
            "technique_id": p.get("technique_id"),
            "technique_name": p.get("technique_name"),
            "confidence": p.get("confidence"),
            "queued_at": p.get("queued_at"),
            "votes": (rec or {}).get("attempts", []),
            "avg_score": (rec or {}).get("avg_score"),
            "backtest_hits": (rec or {}).get("backtest_hits"),
            "healed": len((rec or {}).get("attempts", [])) > 1,
        })
    return JSONResponse({"pending": out})


TECHNIQUE_PLAIN = {
    "t1003.002": "Someone is trying to steal saved Windows passwords from the part of the system that stores them. This is how attackers grab credentials to move deeper.",
    "t1012": "Someone is reading the Windows registry to learn how the machine is set up. Attackers do this to plan their next move.",
    "t1016": "Someone is checking the machine's network settings, its address, gateway, and connections. Attackers map the network before spreading.",
    "t1016.001": "Someone is testing whether the machine can reach the internet. Attackers check this before trying to phone home or download tools.",
    "t1018": "Someone is hunting for other computers on the network. This is how an attacker finds more machines to attack after breaking into one.",
    "t1021.001": "Someone is connecting to this machine using Remote Desktop. Attackers use it to control a computer as if sitting in front of it.",
    "t1021.002": "Someone is connecting to this machine through hidden Windows file shares. Attackers use these to move between computers quietly.",
    "t1033": "Someone is asking who is logged in or who owns this machine. Attackers do this to find valuable accounts to target.",
    "t1035": "Someone is using the Windows service controller to run a program. Attackers abuse this to run code with high privileges.",
    "t1036.005": "A program is pretending to be a trusted, normal Windows file by using a familiar name or location. Attackers do this to hide in plain sight.",
    "t1046": "Someone is scanning the network to find open doors, services and ports they can attack. This is classic early-stage probing before a break-in.",
    "t1048.003": "Someone may be sneaking data out of the network over an unencrypted channel. This is how stolen information leaves the building.",
    "t1049": "Someone is listing the machine's active network connections. Attackers do this to understand what the machine talks to.",
    "t1053.002": "Someone is setting up a hidden scheduled job using the old 'at' command. Attackers use scheduled tasks to keep access or run code later.",
    "t1053.005": "Someone is creating a Windows Scheduled Task. Attackers use these to survive reboots and quietly run code on a timer.",
    "t1055": "A program is injecting its code into another running program. Attackers do this to hide inside a trusted process.",
    "t1057": "Someone is listing the programs currently running. Attackers check this to find security tools or interesting targets.",
    "t1059.001": "Someone is running PowerShell commands. Attackers heavily use PowerShell to run attacks without dropping obvious files.",
    "t1059.003": "Someone is running commands through the Windows command prompt. Attackers use it to chain together quick attack steps.",
    "t1069.002": "Someone is listing the groups in the Windows domain. Attackers do this to find admin groups worth targeting.",
    "t1082": "Someone is collecting basic facts about the machine, its name, version and hardware. Attackers fingerprint a system before deciding how to attack it.",
    "t1083": "Someone is browsing the files and folders on the machine. Attackers do this to find documents and data worth stealing.",
    "t1087.001": "Someone is listing the user accounts on the machine. Attackers do this to find accounts to take over.",
    "t1105": "Someone is downloading a file or tool onto the machine from elsewhere. Attackers do this to bring in their attack tools.",
    "t1110.001": "Someone is guessing passwords by trying many in a row. This is a brute-force attempt to break into an account.",
    "t1112": "Someone is changing the Windows registry. Attackers edit it to disable defenses or keep a foothold.",
    "t1204.002": "Someone opened a file that may be malicious, like a booby-trapped document. This is how many attacks start, a user clicking the wrong thing.",
    "t1216": "Someone is abusing a trusted, signed Windows script to run their own code. Attackers use this to slip past defenses that trust signed files.",
    "t1218.007": "Someone is abusing the trusted Windows installer tool to run code. Attackers use trusted tools so their activity blends in.",
    "t1218.011": "Someone is abusing rundll32, a trusted Windows tool, to run code. This is a very common way attackers hide what they are really doing.",
    "t1482": "Someone is mapping the trust relationships between Windows domains. Attackers use this to plan how to spread across an organization.",
    "t1546.011": "Someone is setting a sneaky trigger that runs their code when certain programs start. Attackers use this to keep access quietly.",
    "t1547.001": "Someone is adding a program to the Windows startup list. Attackers do this so their code runs every time the machine boots.",
    "t1555.004": "Someone is trying to pull saved passwords out of the Windows Credential Manager. Attackers harvest these to log in as someone else.",
    "t1560.001": "Someone is bundling and compressing files, often a sign data is being packaged up to steal.",
    "t1497.001": "A program is checking whether it is running inside a virtual machine or analysis sandbox. Malware does this to avoid being studied, and attackers do it to skip machines that look like traps.",
    "t1564.001": "Someone is hiding files or folders. Attackers do this to keep their tools out of sight.",
    "t1569.002": "Someone is running a program by installing or starting a Windows service. Attackers do this to run code with high privileges and to keep it running.",
    "t1595": "Someone outside is probing this network for open ports and services. This is early-stage reconnaissance, often automated internet-wide scanning, before any real attack.",
    "t1574.010": "Someone is exploiting weak permissions on a Windows service to run their own code. Attackers use this to gain higher privileges.",
    "t1614.001": "Someone is checking the machine's language and region settings. Some attackers use this to avoid hitting machines in certain countries.",
}

def _technique_plain(tags):
    for t in (tags or []):
        tid = str(t).lower().replace("attack.", "").strip()
        if tid in TECHNIQUE_PLAIN:
            return TECHNIQUE_PLAIN[tid]
    # honest fallback: name the technique without faking specifics
    return None


@app.get("/api/pending-detail/{rule_id:path}")
def api_pending_detail(rule_id: str):
    """Return a readable view of a pending rule: title, description, and the raw yaml,
    so the reviewer can see exactly what it would catch before approving."""
    import yaml as _yaml
    rule_id = _require_rule_id(rule_id)
    pdir = HERE / "detections" / "pending"
    fp = pdir / f"{rule_id}.yml"
    if not fp.exists():
        raise HTTPException(status_code=404, detail="rule not found")
    raw = fp.read_text(encoding="utf-8")
    out = {"rule_id": rule_id, "yaml": raw, "title": None, "summary": None,
           "triggers": [], "false_alarms": [], "level": None, "meaning": None, "ai_context": None}
    try:
        doc = _yaml.safe_load(raw)
        out["title"] = doc.get("title")
        out["summary"] = doc.get("description")
        out["level"] = doc.get("level")
        out["meaning"] = _technique_plain(doc.get("tags", []))
        # pull the AI-written context note (if any) from the pending record
        for p in _state("pending_rules.json", []):
            if p.get("rule_id") == rule_id and p.get("ai_context"):
                out["ai_context"] = p["ai_context"]
                break
        out["false_alarms"] = doc.get("falsepositives", []) or []
        # Translate the detection logic into plain human triggers.
        FIELD_PLAIN = {
            "event.code": lambda v: _event_code_plain(v),
            "process.name": lambda v: "the program is " + _join_or(v),
            "process.executable": lambda v: "the program path matches " + _join_or(v),
            "process.parent.name": lambda v: "it was launched by " + _join_or(v),
            "process.parent.executable": lambda v: "the parent program matches " + _join_or(v),
            "process.command_line": lambda v: "the command line contains " + _join_or(v),
            "source.ip": lambda v: "the connection comes from " + _join_or(v),
            "destination.ip": lambda v: "it connects to " + _join_or(v),
            "destination.port": lambda v: "it targets port " + _join_or(v),
            "file.path": lambda v: "the file path matches " + _join_or(v),
            "user.name": lambda v: "the user is " + _join_or(v),
        }
        det = doc.get("detection", {}) or {}
        for key, block in det.items():
            if key == "condition":
                continue
            negate = ("filter" in key.lower() or "exclude" in key.lower())
            if isinstance(block, dict):
                for fld, val in block.items():
                    base = fld.split("|")[0]
                    fn = FIELD_PLAIN.get(base)
                    phrase = fn(val) if fn else (base + " matches " + _join_or(val))
                    if negate:
                        phrase = "NOT when " + phrase
                    out["triggers"].append(phrase)
    except (_yaml.YAMLError, AttributeError, TypeError) as exc:
        # Unparseable / oddly-shaped rule: still return the raw YAML so the reviewer can read it.
        log.warning("could not summarise pending rule %s: %r", rule_id, exc)
    return JSONResponse(out)


def _join_or(v):
    if not isinstance(v, list):
        v = [v]
    v = [str(x).strip("*") for x in v]
    if len(v) == 1:
        return v[0]
    if len(v) <= 4:
        return ", ".join(v[:-1]) + " or " + v[-1]
    return ", ".join(v[:3]) + f" or {len(v)-3} more"


def _event_code_plain(v):
    codes = {"1": "a program starts", "3": "a network connection is made",
             "11": "a file is created", "13": "the registry is changed",
             "7": "a code library loads", "22": "a DNS query is made",
             "8": "a process injects into another"}
    key = str(v[0] if isinstance(v, list) else v)
    return codes.get(key, f"a Sysmon event of type {key} occurs")


def _run_approve_cli(action: str, rule_id: str) -> JSONResponse:
    try:
        r = subprocess.run([sys.executable, str(HERE / "approve.py"), action, rule_id],
                           capture_output=True, text=True, cwd=str(HERE),
                           timeout=APPROVE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        log.error("approve.py %s %s timed out after %ss", action, rule_id, APPROVE_TIMEOUT_SECONDS)
        return JSONResponse({"ok": False, "output": f"timed out after {APPROVE_TIMEOUT_SECONDS}s"},
                            status_code=504)
    ok = r.returncode == 0
    if not ok:
        log.error("approve.py %s %s exited %s", action, rule_id, r.returncode)
    return JSONResponse({"ok": ok, "output": (r.stdout or "") + (r.stderr or "")})


@app.post("/api/approve/{rule_id:path}")
def api_approve(rule_id: str, x_admin_token: str = Header(default=None)):
    _require_admin(x_admin_token)
    return _run_approve_cli("approve", _require_rule_id(rule_id))


@app.post("/api/reject/{rule_id:path}")
def api_reject(rule_id: str, x_admin_token: str = Header(default=None)):
    _require_admin(x_admin_token)
    return _run_approve_cli("reject", _require_rule_id(rule_id))


@app.get("/review")
def review_page():
    return FileResponse(WEB_DIR / "review.html")


@app.get("/engine")
def engine_page():
    return FileResponse(WEB_DIR / "engine.html")


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
