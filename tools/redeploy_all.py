"""One-time, safe bulk redeploy: bring every deployed Kibana rule in line with the shipped Sigma rules.

    python tools/redeploy_all.py [--rules-dir detections/sigma] [--apply [--yes]]
                                 [--allow-retag ID ...] [--report PATH] [--delay SECONDS]
    python tools/redeploy_all.py --suggest-retags [--since fde31e5] [--repo-dir .]

Default is a DRY RUN: it only reads Kibana (GET) and prints what --apply would do. A plan is always
produced in the same invocation before anything is written. Actions:

  CREATE           not in Kibana                                -> create
  UPDATE           same lineage, engine-owned fields differ     -> PATCH engine-owned fields only
  UNCHANGED        all engine-owned fields identical            -> skipped
  DISABLE          status: deprecated and currently enabled     -> disabled (never deleted)
  NOOP-DEPRECATED  deprecated and absent / already disabled     -> skipped
  RETAG-NEEDED     technique tags share no lineage with Kibana's -> blocked unless id is in --allow-retag
  ERROR            conversion failure, HTTP error, missing id   -> skipped, reported

Orphans (rules in Kibana that look like ours but have no shipped file) are only reported; deleting
stays an explicit `deploy_rule.py --delete <id>`. All Kibana writes go through deploy_rule.deploy_to_kibana.

Exit codes: 0 clean; 1 any ERROR / failed write / unapproved RETAG-NEEDED; 2 usage or configuration.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402
import yaml  # noqa: E402

import deploy_rule  # noqa: E402
from lab.config import ConfigError, load  # noqa: E402
from lab.http import session as make_session  # noqa: E402
from lab.kibana_rule import ENGINE_OWNED_FIELDS, build_payload, technique_tags  # noqa: E402

ACTIONS = ("CREATE", "UPDATE", "UNCHANGED", "DISABLE", "NOOP-DEPRECATED", "RETAG-NEEDED", "ERROR")
_UUID_RE = deploy_rule._UUID_RE
_UNORDERED = {"tags", "references", "author", "false_positives", "index"}
FIRST_TAGGED_BASELINE = "fde31e5"


class ReadOnlySession:
    """Wraps a requests session and allows GET only: the dry-run cannot write by construction."""

    def __init__(self, inner):
        self._inner = inner

    def get(self, *a, **kw):
        return self._inner.get(*a, **kw)

    def _deny(self, *a, **kw):
        raise RuntimeError("write attempted through a read-only (dry-run) session")

    post = patch = put = delete = request = head = _deny


# ------------------------------------------------------------------ planning

def _norm(field, value):
    if field in _UNORDERED and isinstance(value, list):
        return sorted(str(v) for v in value)
    return value


def _diff_fields(payload: dict, existing: dict) -> list:
    return [f for f in ENGINE_OWNED_FIELDS
            if f in payload and _norm(f, payload[f]) != _norm(f, existing.get(f))]


def _read_rule(http, settings, headers, rule_id):
    """-> (existing dict | None when absent). Raises on any other outcome."""
    resp = http.get(deploy_rule._url(settings), headers=headers, params={"rule_id": rule_id})
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise deploy_rule.DeployError(f"GET rule {rule_id}: {resp.status_code} {resp.text[:200]}")
    try:
        body = resp.json()
    except ValueError as exc:
        raise deploy_rule.DeployError(f"GET rule {rule_id}: unreadable response") from exc
    if not isinstance(body, dict):
        raise deploy_rule.DeployError(f"GET rule {rule_id}: unexpected response")
    return body


def _entry(file, rule_id, action, detail, **extra):
    e = {"file": file, "rule_id": rule_id, "action": action, "detail": detail}
    e.update(extra)
    return e


def classify(path: Path, rel: str, settings, http, headers, allow_retag: set) -> dict:
    try:
        metadata = deploy_rule.load_rule_metadata(str(path))
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
        return _entry(rel, "", "ERROR", f"unreadable rule file: {exc}".replace("\n", " ")[:300])
    if not isinstance(metadata, dict):
        return _entry(rel, "", "ERROR", "not a Sigma rule mapping")
    rule_id = str(metadata.get("id") or "").strip()
    if not rule_id:
        return _entry(rel, "", "ERROR", "Sigma rule has no id")
    try:
        existing = _read_rule(http, settings, headers, rule_id)
        if str(metadata.get("status") or "").strip().lower() == "deprecated":
            if existing is None:
                return _entry(rel, rule_id, "NOOP-DEPRECATED", "deprecated, not in Kibana")
            if existing.get("enabled") is False:
                return _entry(rel, rule_id, "NOOP-DEPRECATED", "deprecated, already disabled")
            return _entry(rel, rule_id, "DISABLE", "deprecated and enabled in Kibana")
        try:
            queries = [q for q in (deploy_rule.convert_sigma(str(path)) or []) if q]
            if not queries:
                raise ValueError("no query produced")
            author = metadata.get("author")
            payload = build_payload(metadata, queries, str(author) if author else "")
        except Exception as exc:  # pySigma raises many distinct error types
            return _entry(rel, rule_id, "ERROR", f"could not convert: {exc}".replace("\n", " ")[:300])
        if existing is None:
            return _entry(rel, rule_id, "CREATE", f"new rule, query length {len(payload['query'])}")
        if str(existing.get("rule_id") or rule_id) != rule_id:
            return _entry(rel, rule_id, "ERROR", "Kibana returned a different rule_id; refusing")
        fields = _diff_fields(payload, existing)
        old_len = len(str(existing.get("query") or ""))
        new_len = len(payload["query"])
        diff = {"query_len": {"old": old_len, "new": new_len}, "fields": fields}
        try:
            deploy_rule._check_same_lineage(existing, payload, allow_retag=False)
        except deploy_rule.DeployError:
            approved = rule_id in allow_retag
            return _entry(rel, rule_id, "RETAG-NEEDED",
                          f"technique tags {sorted(technique_tags(existing.get('tags')))} -> "
                          f"{sorted(technique_tags(payload['tags']))}; "
                          + ("approved via --allow-retag" if approved else "blocked, needs --allow-retag"),
                          approved=approved, diff=diff)
        if not fields:
            return _entry(rel, rule_id, "UNCHANGED", "engine-owned fields identical")
        return _entry(rel, rule_id, "UPDATE", f"query {old_len}->{new_len}; differs: {', '.join(fields)}",
                      diff=diff)
    except (deploy_rule.DeployError, requests.RequestException) as exc:
        return _entry(rel, rule_id, "ERROR", str(exc).replace("\n", " ")[:300])


def _rule_files(rules_dir: Path) -> list:
    files = [p for p in rules_dir.rglob("*") if p.is_file() and p.suffix.lower() in (".yml", ".yaml")]
    return sorted(files, key=lambda p: p.relative_to(rules_dir).as_posix())


def find_orphans(http, settings, headers, shipped_ids: set, shipped_authors: set):
    """Read-only scan. An orphan: rule_id is a UUID with no shipped file, has an attack.* tag and
    an author equal to a shipped author. Returns (orphans, error or None)."""
    url = deploy_rule._url(settings) + "/_find"
    rules, page = [], 1
    try:
        while page <= 1000:
            resp = http.get(url, headers=headers, params={"per_page": 100, "page": page})
            if resp.status_code != 200:
                return [], f"_find returned {resp.status_code}"
            body = resp.json()
            data = body.get("data") or []
            rules.extend(r for r in data if isinstance(r, dict))
            if not data or len(rules) >= int(body.get("total") or 0):
                break
            page += 1
    except (requests.RequestException, ValueError, AttributeError, TypeError) as exc:
        return [], f"orphan scan failed: {type(exc).__name__}"
    out = []
    for r in rules:
        rid = str(r.get("rule_id") or "")
        tags = [str(t).lower() for t in (r.get("tags") or [])]
        authors = {str(a).strip().lower() for a in (r.get("author") or [])}
        if (_UUID_RE.match(rid) and rid not in shipped_ids and any(t.startswith("attack.") for t in tags)
                and authors & shipped_authors):
            out.append({"rule_id": rid, "name": r.get("name"), "tags": r.get("tags"),
                        "author": r.get("author"), "enabled": r.get("enabled")})
    return out, None


def build_plan(rules_dir, settings, http, allow_retag=frozenset()) -> dict:
    rules_dir = Path(rules_dir)
    headers = deploy_rule._headers(settings)
    entries, ids, authors = [], set(), set()
    for path in _rule_files(rules_dir):
        rel = path.relative_to(rules_dir).as_posix()
        entries.append(classify(path, rel, settings, http, headers, set(allow_retag)))
        if entries[-1]["rule_id"]:
            ids.add(entries[-1]["rule_id"])
        try:
            meta = deploy_rule.load_rule_metadata(str(path))
            if isinstance(meta, dict) and meta.get("author"):
                authors.add(str(meta["author"]).strip().lower())
        except Exception:  # already reported as ERROR above
            pass
    orphans, orphans_error = find_orphans(http, settings, headers, ids, authors)
    return {"plan": entries, "orphans": orphans, "orphans_error": orphans_error}


def summarize(entries) -> dict:
    counts = {a: 0 for a in ACTIONS}
    for e in entries:
        counts[e["action"]] = counts.get(e["action"], 0) + 1
    return counts


# ------------------------------------------------------------------ apply

def apply_plan(entries, rules_dir, settings, session, sleep, delay) -> None:
    rules_dir = Path(rules_dir)
    for e in entries:
        act = e["action"]
        if act in ("CREATE", "UPDATE", "DISABLE"):
            retag = False
        elif act == "RETAG-NEEDED" and e.get("approved"):
            retag = True
        else:
            continue
        try:
            deploy_rule.deploy_to_kibana(str(rules_dir / e["file"]), settings, session, allow_retag=retag)
            e["result"] = "ok"
        except Exception as exc:  # per-rule failure never stops the run
            e["result"] = "failed"
            e["error"] = str(exc).replace("\n", " ")[:300]
        sleep(delay)


def exit_code(entries) -> int:
    for e in entries:
        if e["action"] == "ERROR" or e.get("result") == "failed":
            return 1
        if e["action"] == "RETAG-NEEDED" and not e.get("approved"):
            return 1
    return 0


def print_plan(entries, orphans, orphans_error, out=None) -> None:
    out = out or sys.stdout
    for e in entries:
        res = f"  [{e['result']}]" if e.get("result") else ""
        print(f"{e['action']:<16} {e['file']}  {e['rule_id']}  {e['detail']}{res}", file=out)
        if e.get("error"):
            print(f"{'':<16} error: {e['error']}", file=out)
    if orphans:
        print(f"\nORPHANS (in Kibana, no shipped file; reported only, delete with "
              f"`deploy_rule.py --delete <id>`):", file=out)
        for o in orphans:
            print(f"  {o['rule_id']}  {o.get('name')}", file=out)
    if orphans_error:
        print(f"\nnote: orphan scan unavailable ({orphans_error})", file=out)


def print_summary(entries, out=None) -> None:
    out = out or sys.stdout
    counts = summarize(entries)
    print("\nSummary", file=out)
    for a in ACTIONS:
        print(f"  {a:<16} {counts[a]:>4}", file=out)
    done = sum(1 for e in entries if e.get("result") == "ok")
    failed = sum(1 for e in entries if e.get("result") == "failed")
    if done or failed:
        print(f"  applied ok: {done}, failed: {failed}", file=out)


# ------------------------------------------------------------------ --suggest-retags

def suggest_retags(repo_dir, since, until="HEAD", prefix="detections/sigma") -> list:
    """Rules whose ATT&CK technique tags differ between `since` and `until` (by rule id)."""
    from tools import ci_changes as cc

    def tree(rev):
        r = cc._git(repo_dir, "ls-tree", "-r", "-z", "--name-only", rev, "--", prefix)
        if r.returncode != 0:
            raise RuntimeError(f"git ls-tree {rev} failed: {r.stderr.decode('utf-8', 'replace').strip()}")
        out = {}
        for p in r.stdout.decode("utf-8", "surrogateescape").split("\0"):
            if p and cc._is_rule_path(p, prefix):
                info = cc._rule_info(cc._blob(repo_dir, rev, p))
                if info:
                    out[info["id"]] = dict(info, path=p)
        return out

    old, new = tree(since), tree(until)
    res = []
    for rid in sorted(new, key=lambda i: (new[i]["path"], i)):
        n, o = new[rid], old.get(rid)
        if o is None or n["status"] == "deprecated" or n["tags"] == o["tags"]:
            continue
        shares = {deploy_rule._parent(t) for t in n["tags"]} & {deploy_rule._parent(t) for t in o["tags"]}
        res.append({"rule_id": rid, "file": n["path"], "old": sorted(o["tags"]), "new": sorted(n["tags"]),
                    "needs_allow_retag": not shares})
    return res


# ------------------------------------------------------------------ CLI

def _parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules-dir", default="detections/sigma")
    ap.add_argument("--apply", action="store_true", help="perform the planned writes (default: dry run)")
    ap.add_argument("--yes", action="store_true", help="skip the interactive confirmation for --apply")
    ap.add_argument("--allow-retag", nargs="+", action="extend", default=[], metavar="ID",
                    help="rule ids whose deliberate technique retag may be applied")
    ap.add_argument("--report", metavar="PATH", help="write the full plan/results as JSON")
    ap.add_argument("--delay", type=float, default=0.2, help="seconds to pause after each write (default 0.2)")
    ap.add_argument("--suggest-retags", action="store_true",
                    help="offline: list rules whose technique tags changed since --since (uses git)")
    ap.add_argument("--since", default=FIRST_TAGGED_BASELINE)
    ap.add_argument("--repo-dir", default=".")
    return ap


def main(argv=None, sleep=time.sleep, stdin=None, ask=input, session=None) -> int:
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    stdin = sys.stdin if stdin is None else stdin

    if args.suggest_retags:
        try:
            found = suggest_retags(args.repo_dir, args.since)
        except RuntimeError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 2
        print(f"Rules whose technique tags changed between {args.since} and HEAD ({len(found)}):")
        for f in found:
            flag = "  NEEDS-ALLOW-RETAG" if f["needs_allow_retag"] else ""
            print(f"{f['rule_id']}  {f['file']}  old={f['old']} new={f['new']}{flag}")
        need = [f["rule_id"] for f in found if f["needs_allow_retag"]]
        if need:
            print("\nShare no technique lineage with the old tags; if Kibana still holds the old tags, "
                  "these need:\n  --allow-retag " + " ".join(need))
        return 0

    if args.apply and not args.yes and not stdin.isatty():
        print("FAIL: --apply without --yes needs an interactive terminal; re-run with --yes to confirm",
              file=sys.stderr)
        return 2
    rules_dir = Path(args.rules_dir)
    if not rules_dir.is_dir():
        print(f"FAIL: rules dir {rules_dir} does not exist", file=sys.stderr)
        return 2
    if not os.environ.get("ELASTIC_API_KEY", "").strip() or not os.environ.get("KIBANA_URL", "").strip():
        print("FAIL: ELASTIC_API_KEY and KIBANA_URL must both be set", file=sys.stderr)
        return 2
    try:
        settings = load()
    except ConfigError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    real = session or make_session(verify=settings.verify_tls)
    try:
        result = build_plan(rules_dir, settings, ReadOnlySession(real), set(args.allow_retag))
    except (ConfigError, deploy_rule.DeployError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    entries = result["plan"]
    print(f"{'APPLY' if args.apply else 'DRY RUN'} plan for {len(entries)} rule file(s) in {rules_dir}\n")
    print_plan(entries, result["orphans"], result["orphans_error"])

    if args.apply:
        if not args.yes:
            if ask("\nType 'yes' to apply this plan to Kibana: ").strip().lower() != "yes":
                print("aborted; nothing was written", file=sys.stderr)
                return 2
        apply_plan(entries, rules_dir, settings, real, sleep, args.delay)
    print_summary(entries)
    if not args.apply:
        print("\nDry run: nothing was written. Re-run with --apply to perform the plan.")

    if args.report:
        data = {"mode": "apply" if args.apply else "dry-run",
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "rules_dir": str(rules_dir), "summary": summarize(entries), "plan": entries,
                "orphans": result["orphans"], "orphans_error": result["orphans_error"]}
        Path(args.report).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return exit_code(entries)


if __name__ == "__main__":
    sys.exit(main())
