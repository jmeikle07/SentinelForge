"""
SentinelForge Hunt - web API.
Thin wrapper over sf_hunt. Imports the real logic, never duplicates it.
Serves the concise verdict + source breakdown as JSON, and the static page.

Security model:
  - State-changing routes (/api/approve, /api/reject) require the LAB_ADMIN_TOKEN value in the
    X-Admin-Token header (constant-time compare). With no token configured, or one shorter than
    ADMIN_TOKEN_MIN_LENGTH, they are disabled (403). Repeated wrong tokens lock the client out (429).
  - rule_id path parameters must be UUIDs (no path traversal into the filesystem or subprocess).
  - /api/hunt is a POST (it spends third-party quota and writes the in-memory cache; the IOC stays out
    of URLs, access logs and browser history) and is rate limited per client address.
  - Host headers are checked against an allowlist (SF_ALLOWED_HOSTS) so a DNS-rebinding page cannot
    read a localhost-bound server.
  - Rate limiting keys on request.client.host. Behind a reverse proxy see docs/SETUP.md: uvicorn's
    --proxy-headers (on by default) makes that the X-Forwarded-For value from trusted proxies only.
"""
import hmac
import logging
import os
import re
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
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

import sf_hunt as tk
from lab import coverage
from lab import state as lab_state

log = logging.getLogger(__name__)

app = FastAPI(title="SentinelForge Hunt")

HERE = Path(__file__).resolve().parent
WEB_DIR = HERE / "web"

DEFAULT_ALLOWED_HOSTS = "localhost,127.0.0.1,testserver"


def _allowed_hosts() -> list:
    """Host-header allowlist from SF_ALLOWED_HOSTS (comma separated; '*.example.org' wildcards ok;
    '*' disables the check). Read per request so a changed environment applies without a restart."""
    raw = os.environ.get("SF_ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS)
    return [h.strip() for h in raw.split(",") if h.strip()] or DEFAULT_ALLOWED_HOSTS.split(",")


class _EnvTrustedHostMiddleware(TrustedHostMiddleware):
    """Starlette's TrustedHostMiddleware with an allowlist taken from the environment."""

    async def __call__(self, scope, receive, send):
        hosts = _allowed_hosts()
        self.allowed_hosts = hosts
        self.allow_any = "*" in hosts
        await super().__call__(scope, receive, send)


app.add_middleware(_EnvTrustedHostMiddleware, allowed_hosts=_allowed_hosts(), www_redirect=False)

# Per-client sliding-window limit for /api/hunt (each call fans out to paid/quota'd intel APIs).
HUNT_RATE_LIMIT = int(os.environ.get("SF_HUNT_RATE_LIMIT", "10"))      # requests ...
HUNT_RATE_WINDOW = float(os.environ.get("SF_HUNT_RATE_WINDOW", "60"))  # ... per this many seconds
# Failed approve/reject attempts per client before that client is locked out for the window.
AUTH_FAIL_LIMIT = int(os.environ.get("SF_AUTH_FAIL_LIMIT", "5"))
AUTH_FAIL_WINDOW = float(os.environ.get("SF_AUTH_FAIL_WINDOW", "300"))
ADMIN_TOKEN_MIN_LENGTH = 16

_clock = time.monotonic          # injectable in tests
_rate_hits: dict = defaultdict(deque)
_auth_fails: dict = defaultdict(deque)
_rate_lock = threading.Lock()
_sweep_at: dict = {}

APPROVE_TIMEOUT_SECONDS = 120


def _reset_rate_limits() -> None:
    with _rate_lock:
        _rate_hits.clear()
        _auth_fails.clear()
        _sweep_at.clear()


def _expire(hits: deque, now: float, window: float) -> None:
    while hits and now - hits[0] >= window:
        hits.popleft()


def _sweep(table: dict, window: float, now: float) -> None:
    """Drop clients whose window has fully expired, so the table cannot grow by one entry per
    client address forever. Runs at most about once a minute per table. Call with _rate_lock held."""
    last = _sweep_at.get(id(table))
    if last is not None and now - last < min(window, 60.0):
        return
    _sweep_at[id(table)] = now
    for key in list(table):
        _expire(table[key], now, window)
        if not table[key]:
            del table[key]


def _client_id(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _check_rate_limit(request: Request) -> None:
    """Raise 429 when this client exceeded HUNT_RATE_LIMIT calls in the window.
    Keyed on the socket peer address (see the module docstring for the reverse-proxy caveat)."""
    client = _client_id(request)
    now = _clock()
    with _rate_lock:
        _sweep(_rate_hits, HUNT_RATE_WINDOW, now)
        hits = _rate_hits[client]
        _expire(hits, now, HUNT_RATE_WINDOW)
        if len(hits) >= HUNT_RATE_LIMIT:
            retry = max(1, int(HUNT_RATE_WINDOW - (now - hits[0])) + 1)
            raise HTTPException(status_code=429, detail="rate limit exceeded",
                                headers={"Retry-After": str(retry)})
        hits.append(now)


class StateUnavailable(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=503, detail=detail)


_ABSENT = object()


def _state(name: str, default, expect=None):
    """Read a JSON state file. A missing file is `default` (nothing has happened yet). A corrupt,
    unreadable or wrongly shaped one is an HTTP 503 with an explicit reason: never an empty result
    that would read as "all clear" while rules or history are actually lost. lab.state quarantines a
    corrupt file as <name>.corrupt on first read, so a missing file next to a .corrupt sibling is
    still reported until an operator restores or deletes that file."""
    path = HERE / "state" / name
    quarantine = path.with_suffix(".corrupt")
    try:
        data = lab_state.read(path, default=_ABSENT)
    except lab_state.StateCorrupt as exc:
        log.error("state file %s is corrupt: %s", name, exc)
        raise StateUnavailable(f"{name} is corrupt and was quarantined as {quarantine.name}; "
                               f"restore it from backup or delete the .corrupt file") from None
    except (OSError, TimeoutError) as exc:
        log.error("cannot read state file %s: %s", name, exc)
        raise StateUnavailable(f"{name} cannot be read right now") from None
    if data is _ABSENT:
        if quarantine.exists():
            raise StateUnavailable(f"{name} is missing because a corrupt copy was quarantined as "
                                   f"{quarantine.name}; restore it or delete the .corrupt file")
        return default
    if expect is not None and not isinstance(data, expect):
        log.error("state file %s has unexpected content type %s", name, type(data).__name__)
        raise StateUnavailable(f"{name} has an unexpected format")
    return data


def _require_rule_id(rule_id: str) -> str:
    """Rule ids are UUIDs. Anything else (including '../x') is a 400. Returns canonical form."""
    try:
        return str(uuid.UUID(rule_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=400, detail="rule_id must be a UUID")


def _run_hunt(ioc: str) -> dict:
    ioc, ioc_type, reason = tk.normalize_ioc(ioc)
    if reason:
        # Rejected before any cache or third-party call: private/internal names are never sent out.
        raise HTTPException(status_code=400, detail=reason)

    # In-memory cache only: what visitors look up is never written to disk (see index.html).
    conn = tk.memory_init_ephemeral()
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
            log.warning("external IP enrichment failed: %r", e)   # the IOC itself is not logged
            external = {}
    # No T-Pot data on the web route: bucket_verdict renormalises over the sources that
    # actually answered, so the same inputs give the same verdict as the CLI (which passes
    # real observed data; an empty/errored one carries no weight).
    verdict = tk.bucket_verdict({}, external, ioc_type)

    return {"ioc": ioc, "ioc_type": ioc_type, "supported": True,
            "verdict": verdict, "external": external}


class HuntRequest(BaseModel):
    ioc: str = Field(max_length=300)


@app.post("/api/hunt")
def api_hunt(body: HuntRequest, request: Request):
    _check_rate_limit(request)
    return JSONResponse(_run_hunt(body.ioc))


# ── Engine dashboard data ──────────────────────────────────────────────────────
# Reads the rule engine's real state files. No invented data.
TACTIC_ORDER = list(coverage.TACTICS)
TIMELINE_FIELDS = ("timestamp", "result", "technique_id", "technique_name", "confidence",
                   "rule_id", "lookback")


@app.get("/api/engine")
def api_engine():
    seen = _state("seen_techniques.json", {}, dict)
    hunt_log = [e for e in _state("hunt_log.json", [], list) if isinstance(e, dict)]
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
            if not isinstance(v, dict):
                continue
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

    # newest-first timeline (cap to 60). Whitelisted fields only: raw log entries carry server file
    # paths, exception strings and hunted IOCs, none of which belong in an unauthenticated response.
    timeline = [{k: e[k] for k in TIMELINE_FIELDS if k in e}
                for e in sorted(hunt_log, key=lambda e: str(e.get("timestamp") or ""), reverse=True)[:60]]

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


def _require_admin(token: str, request: Request) -> None:
    """These endpoints CHANGE state (deploy rules). Require the LAB_ADMIN_TOKEN value in the
    X-Admin-Token header. Works behind a reverse proxy (unlike a client-address check, which
    sees only the proxy). With LAB_ADMIN_TOKEN unset, or too short to resist guessing, the routes
    are disabled (fail closed). A client that sends AUTH_FAIL_LIMIT wrong tokens within
    AUTH_FAIL_WINDOW is locked out (429), even if its next token is right."""
    expected = os.environ.get("LAB_ADMIN_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=403, detail="approvals disabled: LAB_ADMIN_TOKEN is not set")
    if len(expected) < ADMIN_TOKEN_MIN_LENGTH:
        raise HTTPException(status_code=403, detail=(
            f"approvals disabled: LAB_ADMIN_TOKEN must be at least {ADMIN_TOKEN_MIN_LENGTH} characters"))
    client = _client_id(request)
    now = _clock()
    with _rate_lock:
        _sweep(_auth_fails, AUTH_FAIL_WINDOW, now)
        fails = _auth_fails.get(client)
        if fails is not None:
            _expire(fails, now, AUTH_FAIL_WINDOW)
            if not fails:
                del _auth_fails[client]
            elif len(fails) >= AUTH_FAIL_LIMIT:
                retry = max(1, int(AUTH_FAIL_WINDOW - (now - fails[0])) + 1)
                raise HTTPException(status_code=429, detail="too many failed attempts; try again later",
                                    headers={"Retry-After": str(retry)})
    if not token or not hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8")):
        with _rate_lock:
            _auth_fails[client].append(now)
        raise HTTPException(status_code=401, detail="missing or invalid admin token")
    with _rate_lock:
        _auth_fails.pop(client, None)


@app.get("/api/pending")
def api_pending():
    """List rules waiting for human approval, with their 3-AI vote receipts."""
    pending = _state("pending_rules.json", [], list)
    validations = _state("rule_validations.json", {}, dict)
    # attach the vote receipt (by rule_id) to each pending rule if we have it
    out = []
    for p in pending:
        if not isinstance(p, dict):
            continue
        rec = validations.get(p.get("rule_id"))
        rec = rec if isinstance(rec, dict) else None
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

_TECHNIQUE_ID = re.compile(r"t\d{4}(?:\.\d{3})?")


def _technique_plain(tags):
    """Plain-language meaning for the first known technique tag. Never None: an unknown technique
    (new rule, retag) or a rule with no technique tag gets honest generic text instead of a blank."""
    unknown = []
    for t in (tags or []):
        tid = str(t).lower().replace("attack.", "").strip()
        if tid in TECHNIQUE_PLAIN:
            return TECHNIQUE_PLAIN[tid]
        if _TECHNIQUE_ID.fullmatch(tid):
            unknown.append(tid.upper())
    if unknown:
        return (f"This rule detects activity mapped to MITRE ATT&CK technique {unknown[0]}. No "
                f"plain-language description has been written for that technique yet, so read the "
                f"details below to see exactly what it looks for.")
    return ("This rule has no MITRE ATT&CK technique tag, so there is no plain-language description "
            "of the behaviour. Read the details below to see exactly what it looks for.")


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
    try:
        raw = fp.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        log.error("cannot read pending rule %s: %r", rule_id, exc)
        raise HTTPException(status_code=500, detail="rule file is unreadable")
    out = {"rule_id": rule_id, "yaml": raw, "title": None, "summary": None,
           "triggers": [], "false_alarms": [], "level": None, "meaning": None, "ai_context": None}
    try:
        doc = _yaml.safe_load(raw)
        out["title"] = doc.get("title")
        out["summary"] = doc.get("description")
        out["level"] = doc.get("level")
        out["meaning"] = _technique_plain(doc.get("tags", []))
        # pull the AI-written context note (if any) from the pending record
        for p in _state("pending_rules.json", [], list):
            if isinstance(p, dict) and p.get("rule_id") == rule_id and p.get("ai_context"):
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
    except (_yaml.YAMLError, AttributeError, TypeError, IndexError, KeyError, ValueError) as exc:
        # Unparseable / oddly-shaped rule: still return the raw YAML so the reviewer can read it.
        log.warning("could not summarise pending rule %s: %r", rule_id, exc)
    return JSONResponse(out)


def _join_or(v):
    if not isinstance(v, list):
        v = [v]
    v = [str(x).strip("*") for x in v]
    if not v:
        return "nothing"
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
    if isinstance(v, list):
        if not v:
            return "any Sysmon event occurs"
        v = v[0]
    key = str(v)
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
def api_approve(rule_id: str, request: Request, x_admin_token: str = Header(default=None)):
    _require_admin(x_admin_token, request)
    return _run_approve_cli("approve", _require_rule_id(rule_id))


@app.post("/api/reject/{rule_id:path}")
def api_reject(rule_id: str, request: Request, x_admin_token: str = Header(default=None)):
    _require_admin(x_admin_token, request)
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
