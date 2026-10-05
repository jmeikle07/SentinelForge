"""CI helper: which Sigma rules changed, which were removed, which are retagged.

Used by .github/workflows/deploy-detections.yml. All git access is via argument
lists (never a shell) and results are written NUL-delimited so file names with
spaces, quotes or newlines survive intact.

    python tools/ci_changes.py plan --after SHA [--event-before SHA | --base-sha SHA] --outdir DIR

Writes to DIR:
  changed.z   paths of added/copied/modified rules and the NEW path of renames
  deploy.z    alternating "deploy"|"retag" and path, one pair per changed rule;
              "retag" = an existing rule id whose ATT&CK technique tags differ from
              the old version (needs deploy_rule.py --allow-retag)
  removed.z   rule ids to retire from Kibana: ids of deleted / renamed-away / edited-away
              rules (read from the BEFORE side) that no file in the new tree carries,
              excluding deprecated rules (deploy disables those) and non-UUID ids
Prints key=value lines (for $GITHUB_OUTPUT): base_sha, any_changed, has_work, counts.

The diff base is the last commit whose run of the workflow succeeded when GitHub can
tell us (so a push whose run was dropped from the queue is still covered), otherwise
the push's own "before" sha, otherwise the parent of the pushed commit.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_REV_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TECH_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def technique_tags(tags) -> frozenset:
    """The attack.tNNNN[.NNN] tags of a rule (lower-cased); anything else is ignored."""
    if not isinstance(tags, list):
        return frozenset()
    return frozenset(t.strip().lower() for t in tags
                     if isinstance(t, str) and _TECH_RE.match(t.strip().lower()))


def _git(repo, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "core.quotepath=off", *args], cwd=str(repo),
                          capture_output=True)


def _valid_rev(rev) -> bool:
    return isinstance(rev, str) and bool(_REV_RE.match(rev))


def _commit_exists(repo, rev) -> bool:
    return _valid_rev(rev) and _git(repo, "cat-file", "-e", f"{rev}^{{commit}}").returncode == 0


def _is_ancestor(repo, anc, desc) -> bool:
    return _git(repo, "merge-base", "--is-ancestor", anc, desc).returncode == 0


def resolve_base(repo, event_before, after, last_success) -> str:
    """Pick the commit to diff from (see module docstring)."""
    if _commit_exists(repo, last_success) and _is_ancestor(repo, last_success, after):
        return last_success
    if _commit_exists(repo, event_before) and event_before != "0" * 40:
        return event_before
    parent = _git(repo, "rev-parse", "--verify", "-q", f"{after}~1")
    if parent.returncode == 0 and parent.stdout.strip():
        return parent.stdout.decode().strip()
    return EMPTY_TREE


def fetch_last_success(env, workflow, branch, opener=urllib.request.urlopen):
    """head_sha of the newest successful run of `workflow` on `branch`, or None on any problem."""
    repo = env.get("GITHUB_REPOSITORY")
    token = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN")
    if not repo or not token:
        return None
    api = env.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    query = urllib.parse.urlencode({"status": "success", "branch": branch, "event": "push",
                                    "per_page": 1})
    url = f"{api}/repos/{repo}/actions/workflows/{urllib.parse.quote(workflow)}/runs?{query}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with opener(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        sha = data["workflow_runs"][0]["head_sha"]
    except Exception as exc:  # network, JSON, shape: all mean "unknown", fall back
        _log(f"note: could not determine the last successful run ({type(exc).__name__}); "
             "using the push's own before-sha")
        return None
    return sha if _valid_rev(sha) else None


def _blob(repo, rev, path):
    r = _git(repo, "show", f"{rev}:{path}")
    return r.stdout if r.returncode == 0 else None


def _rule_info(data):
    if data is None:
        return None
    try:
        rule = yaml.safe_load(data.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError):
        return None
    if not isinstance(rule, dict) or rule.get("id") is None:
        return None
    return {"id": str(rule["id"]).strip(), "status": str(rule.get("status") or "").strip().lower(),
            "tags": technique_tags(rule.get("tags"))}


def _is_rule_path(path: str, prefix: str) -> bool:
    return path.endswith(".yml") and path.startswith(prefix.rstrip("/") + "/")


def _diff(repo, base, after, prefix):
    r = _git(repo, "diff", "-z", "--name-status", "-M", base, after, "--", prefix)
    if r.returncode != 0:
        raise RuntimeError(f"git diff failed: {r.stderr.decode('utf-8', 'replace').strip()}")
    tok = r.stdout.decode("utf-8", "surrogateescape").split("\0")
    i, out = 0, []
    while i < len(tok) and tok[i]:
        status = tok[i][0]
        if status in "RC":
            out.append((status, tok[i + 1], tok[i + 2]))
            i += 3
        else:
            out.append((status, tok[i + 1], tok[i + 1]))
            i += 2
    return out


def _tree_ids(repo, rev, prefix):
    r = _git(repo, "ls-tree", "-r", "-z", "--name-only", rev, "--", prefix)
    ids = set()
    for path in r.stdout.decode("utf-8", "surrogateescape").split("\0"):
        if path and _is_rule_path(path, prefix):
            info = _rule_info(_blob(repo, rev, path))
            if info:
                ids.add(info["id"])
    return ids


def build_plan(repo, event_before, after, prefix, outdir, last_success=None, base_sha=None) -> dict:
    repo, outdir = Path(repo), Path(outdir)
    if not _valid_rev(after) and not (isinstance(after, str) and _commit_exists(repo, after)):
        raise ValueError(f"invalid --after revision: {after!r}")
    base = base_sha if (base_sha and (base_sha == EMPTY_TREE or _commit_exists(repo, base_sha))) \
        else resolve_base(repo, event_before, after, last_success)

    changed, old_sides = [], []  # old_sides: BEFORE-side paths of everything that was touched/removed
    for status, old, new in _diff(repo, base, after, prefix):
        new_ok, old_ok = _is_rule_path(new, prefix), _is_rule_path(old, prefix)
        if status in "RC":
            if new_ok:
                changed.append(new)
            if old_ok and status == "R":
                old_sides.append(old)
        elif status == "D":
            if old_ok:
                old_sides.append(old)
        elif new_ok:  # A, M, T
            changed.append(new)
            if status in "MT":
                old_sides.append(old)

    old_by_id = {}
    for path in old_sides:
        info = _rule_info(_blob(repo, base, path))
        if info is None:
            _log(f"warning: cannot read the old version of {path}; not considered for retire/retag")
            continue
        old_by_id[info["id"]] = info

    deploy, retag_count = [], 0
    for path in changed:
        info = _rule_info(_blob(repo, after, path))
        mode = "deploy"
        if info and info["id"] in old_by_id and info["tags"] != old_by_id[info["id"]]["tags"]:
            mode, retag_count = "retag", retag_count + 1
        deploy.append((mode, path))

    removed = []
    if old_by_id:
        new_ids = _tree_ids(repo, after, prefix)
        for rid, info in old_by_id.items():
            if rid in new_ids:
                continue
            if info["status"] == "deprecated":
                _log(f"note: removed rule {rid} was deprecated; it is already disabled, not deleting")
            elif not _UUID_RE.match(rid):
                _log(f"warning: removed rule has a non-UUID id {rid!r}; cannot delete it from Kibana")
            else:
                removed.append(rid)

    outdir.mkdir(parents=True, exist_ok=True)

    def dump(name, items):
        (outdir / name).write_bytes(
            b"".join(s.encode("utf-8", "surrogateescape") + b"\0" for s in items))

    dump("changed.z", changed)
    dump("deploy.z", [x for pair in deploy for x in pair])
    dump("removed.z", removed)
    return {"base_sha": base, "any_changed": bool(changed), "has_work": bool(changed or removed),
            "changed_count": len(changed), "removed_count": len(removed), "retag_count": retag_count}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--repo-dir", default=".")
    p.add_argument("--after", required=True)
    p.add_argument("--event-before", default="")
    p.add_argument("--base-sha", default="", help="use this base instead of resolving one")
    p.add_argument("--prefix", default="detections/sigma")
    p.add_argument("--outdir", required=True)
    p.add_argument("--workflow", default="deploy-detections.yml")
    p.add_argument("--branch", default="main")
    args = ap.parse_args(argv)
    try:
        last = None
        if not args.base_sha:
            last = fetch_last_success(os.environ, args.workflow, args.branch)
        res = build_plan(args.repo_dir, args.event_before, args.after, args.prefix, args.outdir,
                         last_success=last, base_sha=args.base_sha or None)
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _log(f"diff base {res['base_sha']} -> {args.after}: {res['changed_count']} changed "
         f"({res['retag_count']} retag), {res['removed_count']} removed")
    for k in ("base_sha", "any_changed", "has_work", "changed_count", "removed_count"):
        v = res[k]
        print(f"{k}={str(v).lower() if isinstance(v, bool) else v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
