#!/usr/bin/env python3
"""
SentinelForge - review-gate approval CLI.

The autonomous rule engine (with WATER_REVIEW_GATE=true) holds validated rules in
state/pending_rules.json and the Sigma yaml in detections/pending/ instead of deploying.
This tool lets a human review and approve/reject them. Approving runs the SAME
save_and_push the normal path uses, so an approved rule deploys exactly as before,
just with a human in the loop.

Usage:
  python3 approve.py list                 # show pending rules
  python3 approve.py show <rule_id>       # print the full sigma yaml
  python3 approve.py approve <rule_id>    # deploy it (save_and_push + git)
  python3 approve.py reject <rule_id>     # discard it
"""
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

from lab import state as lab_state

HERE = Path(__file__).resolve().parent
STATE = HERE / "state" / "pending_rules.json"
PENDING_DIR = HERE / "detections" / "pending"

# A rule id (or a prefix of one) is hex digits and dashes only: this keeps '../' and
# path separators out of every filesystem path built from user input.
_ID_PREFIX = re.compile(r"^[0-9a-fA-F-]{1,36}$")


def _fail(msg):
    print(msg)
    sys.exit(1)


def _load():
    try:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        return lab_state.read(STATE, default=[])
    except lab_state.StateCorrupt as exc:
        _fail(f"Pending queue is corrupt and was moved aside: {exc}")


def _save(items):
    lab_state.write(STATE, items)


def cmd_list():
    items = _load()
    if not items:
        print("No rules pending review.")
        return
    print(f"\n  {len(items)} rule(s) pending review:\n")
    for it in items:
        print(f"  {it['rule_id'][:8]}  {it['technique_id']:<12} {it['technique_name']}")
        print(f"            confidence: {it.get('confidence','?')}   queued: {it.get('queued_at','?')[:16]}")
    print("\n  approve:  python3 approve.py approve <rule_id>")
    print("  show:     python3 approve.py show <rule_id>\n")


def _find(prefix):
    if not _ID_PREFIX.match(prefix or ""):
        _fail(f"Invalid rule id '{prefix}': expected hex characters and dashes only")
    items = _load()
    matches = [it for it in items if it["rule_id"].startswith(prefix)]
    if not matches:
        _fail(f"No pending rule matching '{prefix}'")
    if len(matches) > 1:
        _fail(f"Ambiguous '{prefix}' - matches {len(matches)} rules; use more characters")
    it = matches[0]
    if not _ID_PREFIX.match(it["rule_id"]):
        _fail(f"Queue entry has an invalid rule id: {it['rule_id']!r}")
    return it


def cmd_show(prefix):
    it = _find(prefix)
    y = PENDING_DIR / f"{it['rule_id']}.yml"
    print(f"\n  {it['technique_id']} - {it['technique_name']}")
    print(f"  confidence: {it.get('confidence')}   queued: {it.get('queued_at')}\n")
    print(y.read_text(encoding="utf-8") if y.exists() else "(yaml file missing)")


def cmd_approve(prefix):
    it = _find(prefix)
    y = PENDING_DIR / f"{it['rule_id']}.yml"
    if not y.exists():
        _fail("yaml file missing, cannot deploy")
    sigma_yaml = y.read_text(encoding="utf-8")
    # Imported here (not at module import) so list/show/reject stay light and import-safe.
    from generate_rule import save_and_push, load_state, save_state, git_push_state, GitError
    analysis = {"technique_id": it["technique_id"], "technique_name": it["technique_name"],
                "tactic": it.get("tactic"), "confidence": it.get("confidence")}
    push_errors = []
    try:
        filepath = save_and_push(sigma_yaml, analysis, it["rule_id"])
    except GitError as exc:
        push_errors.append(str(exc))
        filepath = str(Path("detections") / "sigma")
    print(f"  approved: {it['technique_id']} {it['technique_name']}")
    print(f"    {filepath}")
    # update state: add to seen + log, remove from pending
    seen, last, log, digest = load_state()
    now = datetime.now(timezone.utc).isoformat()
    seen[it["technique_id"]] = {"technique_name": it["technique_name"], "tactic": it.get("tactic"),
                                "rule_id": it["rule_id"], "deployed_at": now, "confidence": it.get("confidence")}
    log.append({"timestamp": now, "result": "deployed", "technique_id": it["technique_id"],
                "technique_name": it["technique_name"], "confidence": it.get("confidence"),
                "rule_id": it["rule_id"], "filepath": filepath, "approved_by": "human"})
    save_state(seen, last, log, digest)
    try:
        git_push_state()
    except GitError as exc:
        push_errors.append(str(exc))
    items = [x for x in _load() if x["rule_id"] != it["rule_id"]]
    _save(items)
    y.unlink(missing_ok=True)
    print("    pending queue updated.")
    if push_errors:
        _fail("WARNING: approved locally but git publish failed: " + "; ".join(push_errors))


def cmd_reject(prefix):
    it = _find(prefix)
    items = [x for x in _load() if x["rule_id"] != it["rule_id"]]
    _save(items)
    (PENDING_DIR / f"{it['rule_id']}.yml").unlink(missing_ok=True)
    print(f"  rejected + discarded: {it['technique_id']} {it['technique_name']}")


def main(argv=None):
    argv = sys.argv if argv is None else argv
    if len(argv) < 2:
        print(__doc__)
        return
    cmd = argv[1]
    if cmd == "list":
        cmd_list()
    elif cmd == "show" and len(argv) > 2:
        cmd_show(argv[2])
    elif cmd == "approve" and len(argv) > 2:
        cmd_approve(argv[2])
    elif cmd == "reject" and len(argv) > 2:
        cmd_reject(argv[2])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
