#!/usr/bin/env python3
"""
SentinelForge - review-gate approval CLI.

The autonomous rule engine (with WATER_REVIEW_GATE=true) holds validated rules in
state/pending_rules.json and the Sigma yaml in detections/pending/ instead of deploying.
This tool lets a human review and approve/reject them. Approving publishes the rule
(detections/sigma + git) FIRST and only then records it in state, so a failed publish
leaves the rule pending and retryable.

Usage:
  python3 approve.py list                 # show pending rules
  python3 approve.py show <rule_id>       # print the full sigma yaml
  python3 approve.py approve <rule_id>    # deploy it (publish, then update state)
  python3 approve.py reject <rule_id>     # discard it
"""
import os
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

import yaml

from lab import state as lab_state

HERE = Path(__file__).resolve().parent
STATE = HERE / "state" / "pending_rules.json"
PENDING_DIR = HERE / "detections" / "pending"
SIGMA_DIR = HERE / "detections" / "sigma"

# A rule id (or a prefix of one) is hex digits and dashes only: this keeps '../' and
# path separators out of every filesystem path built from user input.
_ID_PREFIX = re.compile(r"^[0-9a-fA-F-]{1,36}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _fail(msg):
    print(msg)
    sys.exit(1)


def _load():
    """The pending queue as a list. Items are NOT validated here (see _entry_id)."""
    try:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        items = lab_state.read(STATE, default=[])
    except lab_state.StateCorrupt as exc:
        _fail(f"Pending queue is corrupt and was moved aside: {exc}")
    except (OSError, TimeoutError) as exc:
        _fail(f"Cannot read the pending queue: {exc}")
    if not isinstance(items, list):
        _fail(f"Pending queue {STATE} is not a JSON list; refusing to touch it")
    return items


def _entry_id(it):
    """The entry's rule id when it is a well-formed queue item, else None (malformed: skipped,
    reported, and never dropped from the queue)."""
    if isinstance(it, dict):
        rid = it.get("rule_id")
        if isinstance(rid, str) and _UUID.match(rid):
            return rid
    return None


def _mutate(path, fn, default, what):
    """lab.state.update with failures reported instead of raised."""
    try:
        return lab_state.update(path, fn, default=default)
    except (lab_state.StateCorrupt, ValueError, TimeoutError, OSError) as exc:
        _fail(f"Cannot update {what}: {exc}")


def _remove_from_queue(rid):
    def drop(cur):
        if not isinstance(cur, list):
            raise ValueError("pending queue is not a JSON list")
        return [x for x in cur if not (isinstance(x, dict) and x.get("rule_id") == rid)]
    _mutate(STATE, drop, [], "the pending queue")


def cmd_list():
    items = _load()
    valid = [it for it in items if _entry_id(it)]
    bad = len(items) - len(valid)
    if not valid and not bad:
        print("No rules pending review.")
        return
    if valid:
        print(f"\n  {len(valid)} rule(s) pending review:\n")
    for it in valid:
        print(f"  {it['rule_id'][:8]}  {str(it.get('technique_id', '?')):<12} {it.get('technique_name', '?')}")
        print(f"            confidence: {it.get('confidence','?')}   queued: {str(it.get('queued_at','?'))[:16]}")
    if bad:
        print(f"\n  {bad} malformed queue entr{'y' if bad == 1 else 'ies'} skipped (left in place in {STATE.name})")
    print("\n  approve:  python3 approve.py approve <rule_id>")
    print("  show:     python3 approve.py show <rule_id>\n")


def _find(prefix):
    if not _ID_PREFIX.match(prefix or ""):
        _fail(f"Invalid rule id '{prefix}': expected hex characters and dashes only")
    matches = [it for it in _load() if (rid := _entry_id(it)) and rid.startswith(prefix)]
    if not matches:
        _fail(f"No pending rule matching '{prefix}'")
    if len(matches) > 1:
        _fail(f"Ambiguous '{prefix}' - matches {len(matches)} rules; use more characters")
    return matches[0]


def cmd_show(prefix):
    it = _find(prefix)
    y = PENDING_DIR / f"{it['rule_id']}.yml"
    print(f"\n  {it.get('technique_id')} - {it.get('technique_name')}")
    print(f"  confidence: {it.get('confidence')}   queued: {it.get('queued_at')}\n")
    print(y.read_text(encoding="utf-8") if y.exists() else "(yaml file missing)")


def _load_pending_rule(gr, it):
    """Read and re-validate the pending YAML for a queue entry. Returns the YAML the engine
    will publish (validated, re-rendered). Fails (exit 1) on anything unexpected."""
    rid = it["rule_id"]
    try:
        y = gr.confined_path(PENDING_DIR, f"{rid}.yml")
    except ValueError as exc:
        _fail(f"Refusing to deploy: {exc}")
    if not y.is_file():
        _fail("yaml file missing, cannot deploy")
    try:
        text = y.read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        _fail(f"Cannot read pending yaml: {exc}")
    if not isinstance(doc, dict) or str(doc.get("id")) != rid:
        _fail("Refusing to deploy: the pending yaml's id does not match the queue entry")
    author = doc.get("author") if isinstance(doc.get("author"), str) else "SentinelForge"
    try:
        rule = gr.validate_generated_sigma(
            text, rule_id=rid, analysis={"technique_id": it["technique_id"]},
            today=str(doc.get("date", "")), author=author, existing_ids=set())
    except gr.RuleValidationError as exc:
        _fail(f"Refusing to deploy: pending rule failed validation: {exc.reason}")
    return gr.render_rule(rule)


def _same_rule_id(path, rid):
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return False
    return isinstance(doc, dict) and str(doc.get("id")) == rid


def _publish(gr, it, content):
    """Write the rule into detections/sigma and publish it (add, commit, pull --rebase, push).
    Idempotent for retries: a file left by an earlier failed attempt for the SAME rule id is
    reused, and the push always runs so a commit that never got pushed is pushed now.
    Raises gr.GitError / OSError / ValueError; returns the repo-relative file path."""
    rid, tid, tname = it["rule_id"], it["technique_id"], it["technique_name"]
    SIGMA_DIR.mkdir(parents=True, exist_ok=True)
    target, created = None, False
    for unique in (False, True):
        cand = gr.confined_path(SIGMA_DIR, gr.safe_rule_filename(tid, tname, rid, unique=unique))
        if cand.exists():
            if _same_rule_id(cand, rid):
                target = cand
                break
            continue
        target, created = cand, True
        break
    if target is None:
        raise ValueError("a different rule already occupies this rule's file name")
    if created:
        target.write_text(content, encoding="utf-8")
    committed = False
    try:
        gr._git("add", str(target))
        gr._commit(f"auto-generate: {gr.sanitize_text(tid, 20)} {gr.sanitize_text(tname, 80)} [{rid[:8]}]")
        committed = True  # now (or already) part of a local commit
        gr._git("pull", "--rebase")
        gr._git("push")
    except BaseException:
        if created and not committed:  # leave no stray, unpublished file behind
            target.unlink(missing_ok=True)
            try:
                gr._git("reset", "-q", "--", str(target))
            except gr.GitError:
                pass
        raise
    return os.path.join(gr.SIGMA_OUTPUT_DIR, target.name)


def cmd_approve(prefix):
    it = _find(prefix)
    tid, tname = it.get("technique_id"), it.get("technique_name")
    if not (isinstance(tid, str) and _TECHNIQUE.match(tid) and isinstance(tname, str) and tname.strip()):
        _fail(f"Queue entry {it['rule_id'][:8]} is malformed (technique id/name); cannot deploy it. "
              f"Reject it with: python3 approve.py reject {it['rule_id'][:8]}")
    # Imported here (not at module import) so list/show/reject stay light and import-safe.
    import generate_rule as gr
    content = _load_pending_rule(gr, it)

    # 1. PUBLISH FIRST. Nothing in state or the queue changes unless this succeeds.
    try:
        filepath = _publish(gr, it, content)
    except (gr.GitError, OSError, ValueError) as exc:
        _fail(f"Publish failed: {exc}\n  The rule is still pending (queue and yaml untouched); "
              f"fix git and re-run: python3 approve.py approve {it['rule_id'][:8]}")
    print(f"  approved: {tid} {tname}")
    print(f"    {filepath}")

    # 2. Only now record it. Each file is one lab.state.update of its latest on-disk value, so a
    # concurrent engine run or approve is never overwritten. The queue entry goes last: if we die
    # between steps, a retry re-publishes idempotently and finishes the bookkeeping.
    now = datetime.now(timezone.utc).isoformat()
    rid = it["rule_id"]
    state_dir = STATE.parent

    def add_seen(cur):
        cur = {} if cur is None else cur
        if not isinstance(cur, dict):
            raise ValueError("seen_techniques.json is not a JSON object")
        return {**cur, tid: {"technique_name": tname, "tactic": it.get("tactic"), "rule_id": rid,
                             "deployed_at": now, "confidence": it.get("confidence")}}

    def add_log(cur):
        cur = [] if cur is None else cur
        if not isinstance(cur, list):
            raise ValueError("hunt_log.json is not a JSON list")
        if any(isinstance(e, dict) and e.get("result") == "deployed" and e.get("rule_id") == rid for e in cur):
            return cur
        return cur + [{"timestamp": now, "result": "deployed", "technique_id": tid,
                       "technique_name": tname, "confidence": it.get("confidence"),
                       "rule_id": rid, "filepath": filepath, "approved_by": "human"}]

    errors = []
    try:
        _mutate(state_dir / "seen_techniques.json", add_seen, {}, "seen_techniques.json")
        _mutate(state_dir / "hunt_log.json", add_log, [], "hunt_log.json")
        _remove_from_queue(rid)
    except SystemExit:
        print("  The rule IS published; re-run approve to finish the bookkeeping (it is idempotent).")
        raise
    try:
        gr.confined_path(PENDING_DIR, f"{rid}.yml").unlink(missing_ok=True)
    except (OSError, ValueError) as exc:
        errors.append(f"could not remove pending yaml: {exc}")
    print("    pending queue updated.")
    try:
        gr.git_push_state()
    except gr.GitError as exc:
        errors.append(f"state push failed: {exc}")
    if errors:
        _fail("WARNING: rule deployed, but: " + "; ".join(errors))


def cmd_reject(prefix):
    it = _find(prefix)
    _remove_from_queue(it["rule_id"])
    (PENDING_DIR / f"{it['rule_id']}.yml").unlink(missing_ok=True)
    print(f"  rejected + discarded: {it.get('technique_id')} {it.get('technique_name')}")


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
