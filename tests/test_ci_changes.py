"""Behavioural tests for tools/ci_changes.py (changed/removed/retag planning for CI).

Everything runs against throw-away git repositories; no network.
"""
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import ci_changes  # noqa: E402

PREFIX = "detections/sigma"
ID_A = "11111111-1111-4111-8111-111111111111"
ID_B = "22222222-2222-4222-8222-222222222222"
ID_C = "33333333-3333-4333-8333-333333333333"


def rule(rid, tags=("attack.execution", "attack.t1059.001"), status="experimental", title="t"):
    tag_lines = "\n".join(f"- {t}" for t in tags)
    return f"title: {title}\nid: {rid}\nstatus: {status}\ntags:\n{tag_lines}\n"


class Repo:
    def __init__(self, path):
        self.path = path
        path.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q")
        self.git("config", "user.name", "t")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args):
        r = subprocess.run(["git", *args], cwd=self.path, capture_output=True, text=True,
                           encoding="utf-8")
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    def write(self, rel, text):
        p = self.path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")

    def commit(self, msg="c"):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", msg)
        return self.git("rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    return Repo(tmp_path / "r")


def plan(repo, before, after, tmp_path, **kw):
    out = tmp_path / "plan"
    res = ci_changes.build_plan(repo.path, before, after, PREFIX, out, **kw)
    return res, out


def zlist(path):
    data = (path).read_bytes().decode("utf-8")
    return [x for x in data.split("\0") if x]


def pairs(path):
    items = zlist(path)
    return list(zip(items[0::2], items[1::2]))


def rel(name):
    return f"{PREFIX}/{name}"


# ---- changed / removed -------------------------------------------------------

def test_added_and_modified_rules_are_changed(repo, tmp_path):
    repo.write(rel("a.yml"), rule(ID_A))
    b = repo.commit()
    repo.write(rel("a.yml"), rule(ID_A, title="edited"))
    repo.write(rel("b.yml"), rule(ID_B))
    a = repo.commit()
    res, out = plan(repo, b, a, tmp_path)
    assert sorted(zlist(out / "changed.z")) == [rel("a.yml"), rel("b.yml")]
    assert zlist(out / "removed.z") == []
    assert res["any_changed"] is True and res["has_work"] is True


def test_non_rule_files_and_other_dirs_are_ignored(repo, tmp_path):
    b = repo.commit()
    repo.write(rel("notes.txt"), "x")
    repo.write("docs/x.yml", rule(ID_A))
    a = repo.commit()
    res, out = plan(repo, b, a, tmp_path)
    assert zlist(out / "changed.z") == []
    assert res["has_work"] is False


def test_deleted_rule_is_removed_with_id_from_before_sha(repo, tmp_path):
    repo.write(rel("a.yml"), rule(ID_A))
    b = repo.commit()
    repo.git("rm", "-q", rel("a.yml"))
    a = repo.commit()
    res, out = plan(repo, b, a, tmp_path)
    assert zlist(out / "removed.z") == [ID_A]
    assert zlist(out / "changed.z") == []
    assert res["has_work"] is True and res["any_changed"] is False


def test_pure_rename_is_changed_not_removed(repo, tmp_path):
    repo.write(rel("old.yml"), rule(ID_A))
    b = repo.commit()
    repo.git("mv", rel("old.yml"), rel("new.yml"))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert zlist(out / "changed.z") == [rel("new.yml")]
    assert zlist(out / "removed.z") == []


def test_rename_that_changes_the_id_removes_the_old_id(repo, tmp_path):
    repo.write(rel("old.yml"), rule(ID_A, title="same body " * 30))
    b = repo.commit()
    repo.git("mv", rel("old.yml"), rel("new.yml"))
    repo.write(rel("new.yml"), rule(ID_B, title="same body " * 30))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert zlist(out / "changed.z") == [rel("new.yml")]
    assert zlist(out / "removed.z") == [ID_A]


def test_edit_that_changes_the_id_removes_the_old_id(repo, tmp_path):
    repo.write(rel("a.yml"), rule(ID_A))
    b = repo.commit()
    repo.write(rel("a.yml"), rule(ID_B))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert zlist(out / "removed.z") == [ID_A]


def test_deleted_file_whose_id_lives_on_in_another_file_is_not_removed(repo, tmp_path):
    repo.write(rel("a.yml"), rule(ID_A))
    b = repo.commit()
    repo.git("rm", "-q", rel("a.yml"))
    repo.write(rel("elsewhere.yml"), rule(ID_A, title="moved and rewritten entirely"))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert zlist(out / "removed.z") == []
    assert zlist(out / "changed.z") == [rel("elsewhere.yml")]


def test_deprecated_rule_is_not_deleted(repo, tmp_path):
    repo.write(rel("a.yml"), rule(ID_A, status="deprecated"))
    b = repo.commit()
    repo.git("rm", "-q", rel("a.yml"))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert zlist(out / "removed.z") == []


def test_non_uuid_or_unreadable_removed_rules_are_skipped(repo, tmp_path, capsys):
    repo.write(rel("a.yml"), rule("not-a-uuid"))
    repo.write(rel("b.yml"), "key: [unclosed\n")
    repo.write(rel("c.yml"), rule(ID_C))
    b = repo.commit()
    repo.git("rm", "-q", rel("a.yml"), rel("b.yml"), rel("c.yml"))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert zlist(out / "removed.z") == [ID_C]
    err = capsys.readouterr().err
    assert "not-a-uuid" in err or "a.yml" in err


ODD_NAMES = ["with space.yml", "semi;colon.yml", "dollar$(touch pwned).yml",
             "quote's'q.yml", "ünïcode é.yml", "back`tick`.yml", "-dash.yml"]


def test_odd_filenames_round_trip_exactly(repo, tmp_path):
    b = repo.commit()
    for i, n in enumerate(ODD_NAMES):
        repo.write(rel(n), rule(f"{i:08d}-1111-4111-8111-111111111111"))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert sorted(zlist(out / "changed.z")) == sorted(rel(n) for n in ODD_NAMES)
    assert not (repo.path / "pwned").exists()


def test_odd_filenames_removed(repo, tmp_path):
    for i, n in enumerate(ODD_NAMES):
        repo.write(rel(n), rule(f"{i:08d}-1111-4111-8111-111111111111"))
    b = repo.commit()
    repo.git("rm", "-q", "-r", PREFIX)
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert len(zlist(out / "removed.z")) == len(ODD_NAMES)


# ---- retag ------------------------------------------------------------------

def test_new_rule_never_gets_retag(repo, tmp_path):
    b = repo.commit()
    repo.write(rel("n.yml"), rule(ID_A))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert pairs(out / "deploy.z") == [("deploy", rel("n.yml"))]


def test_changed_technique_tag_gets_retag(repo, tmp_path):
    repo.write(rel("a.yml"), rule(ID_A, ("attack.execution", "attack.t1059.001")))
    b = repo.commit()
    repo.write(rel("a.yml"), rule(ID_A, ("attack.persistence", "attack.t1547.001")))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert pairs(out / "deploy.z") == [("retag", rel("a.yml"))]


def test_edit_keeping_techniques_is_plain_deploy(repo, tmp_path):
    repo.write(rel("a.yml"), rule(ID_A, ("attack.execution", "attack.t1059.001")))
    b = repo.commit()
    repo.write(rel("a.yml"), rule(ID_A, ("cert.secplus.2.4", "attack.t1059.001", "attack.execution"),
                                  title="reworded"))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert pairs(out / "deploy.z") == [("deploy", rel("a.yml"))]


def test_tag_case_is_normalised(repo, tmp_path):
    repo.write(rel("a.yml"), rule(ID_A, ("attack.T1059.001",)))
    b = repo.commit()
    repo.write(rel("a.yml"), rule(ID_A, ("attack.t1059.001",), title="x"))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert pairs(out / "deploy.z") == [("deploy", rel("a.yml"))]


def test_rename_plus_retag_gets_retag(repo, tmp_path):
    repo.write(rel("old.yml"), rule(ID_A, ("attack.t1059.001",), title="body " * 40))
    b = repo.commit()
    repo.git("mv", rel("old.yml"), rel("new.yml"))
    repo.write(rel("new.yml"), rule(ID_A, ("attack.t1218.011",), title="body " * 40))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert pairs(out / "deploy.z") == [("retag", rel("new.yml"))]


def test_delete_then_readd_under_new_name_with_new_technique_is_retag(repo, tmp_path):
    repo.write(rel("old.yml"), rule(ID_A, ("attack.t1059.001",)))
    b = repo.commit()
    repo.git("rm", "-q", rel("old.yml"))
    repo.write(rel("fresh.yml"), rule(ID_A, ("attack.t1546.011",), title="completely different"))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert pairs(out / "deploy.z") == [("retag", rel("fresh.yml"))]
    assert zlist(out / "removed.z") == []


def test_only_one_of_two_changed_rules_is_retagged(repo, tmp_path):
    repo.write(rel("a.yml"), rule(ID_A, ("attack.t1059.001",)))
    repo.write(rel("b.yml"), rule(ID_B, ("attack.t1003.002",)))
    b = repo.commit()
    repo.write(rel("a.yml"), rule(ID_A, ("attack.t1059.001",), title="e"))
    repo.write(rel("b.yml"), rule(ID_B, ("attack.t1055",)))
    a = repo.commit()
    _, out = plan(repo, b, a, tmp_path)
    assert dict((p, m) for m, p in pairs(out / "deploy.z")) == {
        rel("a.yml"): "deploy", rel("b.yml"): "retag"}


def test_technique_tags_helper():
    assert ci_changes.technique_tags(
        ["attack.T1059.001", "attack.execution", "cert.x", "attack.t1055", "attack.t10599", 5]
    ) == frozenset({"attack.t1059.001", "attack.t1055"})
    assert ci_changes.technique_tags(None) == frozenset()
    assert ci_changes.technique_tags("attack.t1059") == frozenset()


# ---- base resolution --------------------------------------------------------

def three_commits(repo):
    repo.write(rel("a.yml"), rule(ID_A))
    c1 = repo.commit("1")
    repo.write(rel("b.yml"), rule(ID_B))
    c2 = repo.commit("2")
    repo.write(rel("c.yml"), rule(ID_C))
    c3 = repo.commit("3")
    return c1, c2, c3


def test_base_uses_event_before_without_last_success(repo):
    c1, c2, c3 = three_commits(repo)
    assert ci_changes.resolve_base(repo.path, c2, c3, None) == c2


def test_base_prefers_last_deployed_sha_so_skipped_push_is_covered(repo, tmp_path):
    c1, c2, c3 = three_commits(repo)
    base = ci_changes.resolve_base(repo.path, c2, c3, c1)
    assert base == c1
    _, out = plan(repo, c2, c3, tmp_path, last_success=c1)
    assert sorted(zlist(out / "changed.z")) == [rel("b.yml"), rel("c.yml")]


def test_base_ignores_last_success_that_is_not_an_ancestor(repo):
    c1, c2, c3 = three_commits(repo)
    repo.git("checkout", "-q", "-b", "side", c1)
    repo.write("x.txt", "x")
    side = repo.commit("side")
    assert ci_changes.resolve_base(repo.path, c2, c3, side) == c2


def test_base_zero_or_unknown_before_falls_back_to_parent(repo):
    c1, c2, c3 = three_commits(repo)
    assert ci_changes.resolve_base(repo.path, "0" * 40, c3, None) == c2
    assert ci_changes.resolve_base(repo.path, "f" * 40, c3, None) == c2
    assert ci_changes.resolve_base(repo.path, "", c3, None) == c2


def test_base_first_commit_uses_empty_tree(repo, tmp_path):
    repo.write(rel("a.yml"), rule(ID_A))
    c1 = repo.commit()
    assert ci_changes.resolve_base(repo.path, "0" * 40, c1, None) == ci_changes.EMPTY_TREE
    _, out = plan(repo, "0" * 40, c1, tmp_path)
    assert zlist(out / "changed.z") == [rel("a.yml")]


def test_option_looking_revisions_are_rejected(repo):
    c1, c2, c3 = three_commits(repo)
    assert ci_changes.resolve_base(repo.path, "--output=/tmp/x", c3, "-p") == c2


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_fetch_last_success_parses_api_and_sends_token(monkeypatch):
    seen = {}

    def opener(req, timeout=None):
        seen["url"] = req.full_url
        seen["auth"] = req.get_header("Authorization")
        return FakeResp(json.dumps({"workflow_runs": [{"head_sha": "ab" * 20}]}).encode())

    env = {"GITHUB_REPOSITORY": "o/r", "GH_TOKEN": "tok"}
    sha = ci_changes.fetch_last_success(env, "deploy-detections.yml", "main", opener=opener)
    assert sha == "ab" * 20
    assert "/repos/o/r/actions/workflows/deploy-detections.yml/runs" in seen["url"]
    assert "status=success" in seen["url"] and "branch=main" in seen["url"]
    assert seen["auth"] == "Bearer tok"


@pytest.mark.parametrize("payload", [b"not json", b'{"workflow_runs": []}', b'{"workflow_runs": [{"head_sha": "zz"}]}',
                                     b"[]"])
def test_fetch_last_success_bad_payload_is_none(payload):
    env = {"GITHUB_REPOSITORY": "o/r", "GH_TOKEN": "tok"}
    assert ci_changes.fetch_last_success(env, "w.yml", "main", opener=lambda r, timeout=None: FakeResp(payload)) is None


def test_fetch_last_success_network_error_and_missing_env_are_none():
    def boom(req, timeout=None):
        raise OSError("offline")
    env = {"GITHUB_REPOSITORY": "o/r", "GH_TOKEN": "tok"}
    assert ci_changes.fetch_last_success(env, "w.yml", "main", opener=boom) is None
    assert ci_changes.fetch_last_success({}, "w.yml", "main", opener=boom) is None


# ---- CLI --------------------------------------------------------------------

def test_cli_prints_github_output_lines(repo, tmp_path, capsys):
    repo.write(rel("a.yml"), rule(ID_A))
    b = repo.commit()
    repo.git("rm", "-q", rel("a.yml"))
    repo.write(rel("b.yml"), rule(ID_B))
    a = repo.commit()
    rc = ci_changes.main(["plan", "--repo-dir", str(repo.path), "--event-before", b, "--after", a,
                          "--outdir", str(tmp_path / "o")])
    assert rc == 0
    lines = dict(l.split("=", 1) for l in capsys.readouterr().out.splitlines())
    assert lines["base_sha"] == b
    assert lines["any_changed"] == "true" and lines["has_work"] == "true"
    assert lines["removed_count"] == "1" and lines["changed_count"] == "1"


def test_cli_with_explicit_base_sha_skips_api(repo, tmp_path, capsys, monkeypatch):
    c1, c2, c3 = three_commits(repo)
    monkeypatch.setattr(ci_changes, "fetch_last_success",
                        lambda *a, **k: pytest.fail("API must not be called"))
    rc = ci_changes.main(["plan", "--repo-dir", str(repo.path), "--base-sha", c1, "--after", c3,
                          "--outdir", str(tmp_path / "o")])
    assert rc == 0
    assert len(zlist(tmp_path / "o" / "changed.z")) == 2


# ---- shell scripts (scripts/ci_*.sh), run with bash against stub python ------

import os  # noqa: E402
import shutil  # noqa: E402

BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(BASH is None, reason="bash not available")
SCRIPTS = ROOT / "scripts"

FAKEPY = """#!/usr/bin/env bash
# logs argv ('|' separated) and fails when FAKE_FAIL occurs in the arguments
printf '%s\\n' "$(IFS='|'; echo "$*")" >> "$FAKE_LOG"
if [ "${1:-}" = "tools/tag_compliance.py" ] && [ -n "${FAKE_TAG:-}" ]; then
  last="${@: -1}"
  if [ -n "${FAKE_TAG_FAIL:-}" ]; then
    case "$last" in *"$FAKE_TAG_FAIL"*) exit 2;; esac
  fi
  echo "# compliance" >> "$last"
fi
if [ -n "${FAKE_FAIL:-}" ]; then
  case "$*" in *"$FAKE_FAIL"*) exit 1;; esac
fi
exit 0
"""


def run_script(name, cwd, *args, env=None):
    e = dict(os.environ, PYTHON="./fakepy", FAKE_LOG=str(Path(cwd) / "calls.log"))
    e.update(env or {})
    return subprocess.run([BASH, str(SCRIPTS / name), *args], cwd=str(cwd), env=e,
                          capture_output=True, text=True, encoding="utf-8")


def calls(cwd):
    p = Path(cwd) / "calls.log"
    return p.read_text(encoding="utf-8").splitlines() if p.exists() else []


def write_z(path, items):
    path.write_bytes(b"".join(s.encode("utf-8") + b"\0" for s in items))


@pytest.fixture
def work(tmp_path):
    w = tmp_path / "w"
    w.mkdir()
    fakepy = w / "fakepy"
    fakepy.write_text(FAKEPY, encoding="utf-8", newline="\n")
    fakepy.chmod(0o755)
    (w / "plan").mkdir()
    return w


SHELL_NAMES = ["plain.yml", "with space.yml", "semi;colon $(touch pwned).yml", "ünï.yml"]


@needs_bash
def test_deploy_script_flags_retag_only_and_handles_odd_names(work):
    items = []
    for i, n in enumerate(SHELL_NAMES):
        (work / rel(n)).parent.mkdir(parents=True, exist_ok=True)
        (work / rel(n)).write_text("x", encoding="utf-8")
        items += ["retag" if i == 1 else "deploy", rel(n)]
    write_z(work / "plan" / "deploy.z", items)
    write_z(work / "plan" / "removed.z", [ID_A, ID_B])
    r = run_script("ci_deploy.sh", work, "plan")
    assert r.returncode == 0, r.stderr
    assert calls(work) == [
        f"deploy_rule.py|{rel('plain.yml')}",
        f"deploy_rule.py|{rel('with space.yml')}|--allow-retag",
        f"deploy_rule.py|{rel('semi;colon $(touch pwned).yml')}",
        f"deploy_rule.py|{rel('ünï.yml')}",
        f"deploy_rule.py|--delete|{ID_A}",
        f"deploy_rule.py|--delete|{ID_B}",
    ]
    assert not (work / "pwned").exists()


@needs_bash
def test_deploy_script_keeps_going_and_fails_at_the_end(work):
    for n in ("a.yml", "b.yml"):
        (work / rel(n)).parent.mkdir(parents=True, exist_ok=True)
        (work / rel(n)).write_text("x", encoding="utf-8")
    write_z(work / "plan" / "deploy.z", ["deploy", rel("a.yml"), "deploy", rel("b.yml")])
    write_z(work / "plan" / "removed.z", [ID_A])
    r = run_script("ci_deploy.sh", work, "plan", env={"FAKE_FAIL": "a.yml"})
    assert r.returncode == 1
    assert len(calls(work)) == 3  # b.yml and the delete still ran


@needs_bash
def test_deploy_script_missing_file_fails(work):
    write_z(work / "plan" / "deploy.z", ["deploy", rel("gone.yml")])
    r = run_script("ci_deploy.sh", work, "plan")
    assert r.returncode == 1 and calls(work) == []


@needs_bash
def test_validate_script_collects_failures_and_never_stops(work):
    names = ["a.yml", "bad.yml", "c d.yml"]
    for n in names:
        (work / rel(n)).parent.mkdir(parents=True, exist_ok=True)
        (work / rel(n)).write_text("x", encoding="utf-8")
    write_z(work / "plan" / "changed.z", [rel(n) for n in names] + [rel("missing.yml")])
    r = run_script("ci_validate.sh", work, "plan", env={"FAKE_FAIL": "bad.yml"})
    assert r.returncode == 0
    assert zlist(work / "plan" / "passed.z") == [rel("a.yml"), rel("c d.yml")]
    assert zlist(work / "plan" / "failed.z") == [rel("bad.yml"), rel("missing.yml")]
    assert calls(work) == [f"validate_rule.py|{rel(n)}" for n in names]


@needs_bash
def test_validate_script_with_no_changes(work):
    r = run_script("ci_validate.sh", work, "plan")
    assert r.returncode == 0 and zlist(work / "plan" / "passed.z") == []


def git_in(path, *args):
    r = subprocess.run(["git", *args], cwd=str(path), capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


@pytest.fixture
def healrepo(work):
    git_in(work, "init", "-q")
    git_in(work, "config", "user.name", "t")
    git_in(work, "config", "user.email", "t@example.invalid")
    git_in(work, "config", "core.autocrlf", "false")
    git_in(work, "config", "commit.gpgsign", "false")
    for n in ("good.yml", "bad.yml", "weird [1].yml"):
        (work / rel(n)).parent.mkdir(parents=True, exist_ok=True)
        (work / rel(n)).write_text("orig\n", encoding="utf-8", newline="\n")
    (work / ".gitignore").write_text("calls.log\nfakepy\nplan/\nout.txt\n")
    git_in(work, "add", "-A")
    git_in(work, "commit", "-q", "-m", "init")
    return work


@needs_bash
def test_heal_commits_passed_rules_tagged_and_restores_failed(healrepo):
    w = healrepo
    (w / rel("good.yml")).write_text("orig\n# healed\n", newline="\n")
    (w / rel("weird [1].yml")).write_text("orig\n# healed\n", newline="\n")
    (w / rel("bad.yml")).write_text("orig\n# half healed\n", newline="\n")
    write_z(w / "plan" / "passed.z", [rel("good.yml"), rel("weird [1].yml")])
    write_z(w / "plan" / "failed.z", [rel("bad.yml")])
    r = run_script("ci_heal.sh", w, "plan", env={"FAKE_TAG": "1", "GITHUB_OUTPUT": str(w / "out.txt")})
    assert r.returncode == 0, r.stderr
    assert (w / "out.txt").read_text().strip() == "committed=true"
    assert "[skip ci]" in git_in(w, "log", "-1", "--format=%B")
    files = git_in(w, "show", "--name-only", "--format=", "HEAD").splitlines()
    assert sorted(files) == sorted([rel("good.yml"), rel("weird [1].yml")])
    assert "# compliance" in (w / rel("good.yml")).read_text()
    assert (w / rel("bad.yml")).read_text() == "orig\n"          # restored, not committed
    assert git_in(w, "status", "--porcelain") == ""
    assert calls(w) == [
        f"tools/tag_compliance.py|--write|--files|{rel('good.yml')}",
        f"tools/tag_compliance.py|--write|--files|{rel('weird [1].yml')}"]


@needs_bash
def test_heal_unmapped_technique_logs_and_still_commits(healrepo):
    w = healrepo
    (w / rel("good.yml")).write_text("orig\n# healed\n", newline="\n")
    write_z(w / "plan" / "passed.z", [rel("good.yml")])
    write_z(w / "plan" / "failed.z", [])
    r = run_script("ci_heal.sh", w, "plan",
                   env={"FAKE_TAG": "1", "FAKE_TAG_FAIL": "good.yml", "GITHUB_OUTPUT": str(w / "out.txt")})
    assert r.returncode == 0
    assert "compliance tagging skipped" in r.stdout
    assert "# compliance" not in (w / rel("good.yml")).read_text()
    assert (w / "out.txt").read_text().strip() == "committed=true"


@needs_bash
def test_heal_nothing_to_commit(healrepo):
    w = healrepo
    write_z(w / "plan" / "passed.z", [rel("good.yml")])
    write_z(w / "plan" / "failed.z", [])
    before = git_in(w, "rev-parse", "HEAD")
    r = run_script("ci_heal.sh", w, "plan", env={"GITHUB_OUTPUT": str(w / "out.txt")})
    assert r.returncode == 0
    assert git_in(w, "rev-parse", "HEAD") == before
    assert (w / "out.txt").read_text().strip() == "committed=false"


@pytest.fixture
def pushrepo(tmp_path):
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(remote), str(clone)], check=True, capture_output=True)
    for k, v in (("user.name", "t"), ("user.email", "t@example.invalid"), ("core.autocrlf", "false"),
                 ("commit.gpgsign", "false")):
        git_in(clone, "config", k, v)
    git_in(clone, "checkout", "-q", "-B", "main")
    (clone / "f.txt").write_text("base\n", newline="\n")
    git_in(clone, "add", "-A")
    git_in(clone, "commit", "-q", "-m", "base")
    git_in(clone, "push", "-q", "origin", "main")
    return remote, clone


def run_push(clone, token="tok", args=("main",)):
    env = {k: v for k, v in os.environ.items() if k != "GH_TOKEN"}
    if token is not None:
        env["GH_TOKEN"] = token
    return subprocess.run([BASH, str(SCRIPTS / "ci_push.sh"), *args], cwd=str(clone), env=env,
                          capture_output=True, text=True)


def heal_commit(clone):
    (clone / "g.txt").write_text("heal\n", newline="\n")
    git_in(clone, "add", "-A")
    git_in(clone, "commit", "-q", "-m", "heal")


@needs_bash
def test_push_script_publishes_without_storing_the_token(pushrepo):
    remote, clone = pushrepo
    heal_commit(clone)
    r = run_push(clone, "s3cret-token")
    assert r.returncode == 0, r.stderr
    assert git_in(remote, "log", "-1", "--format=%s", "main") == "heal"
    cfg = (clone / ".git" / "config").read_text()
    assert "s3cret-token" not in cfg and "extraheader" not in cfg
    assert "s3cret-token" not in r.stdout + r.stderr


@needs_bash
def test_push_script_fails_loudly_when_push_is_rejected(pushrepo):
    remote, clone = pushrepo
    (remote / "hooks" / "pre-receive").write_text("#!/bin/sh\necho 'protected branch' >&2\nexit 1\n",
                                                  newline="\n")
    os.chmod(remote / "hooks" / "pre-receive", 0o755)
    heal_commit(clone)
    r = run_push(clone)
    out = r.stdout + r.stderr
    assert r.returncode != 0
    assert "branch protection" in out and "NOT published" in out


@needs_bash
def test_push_script_rebase_conflict_fails_and_aborts_rebase(pushrepo, tmp_path):
    remote, clone = pushrepo
    other = tmp_path / "other"
    subprocess.run(["git", "clone", "-q", str(remote), str(other)], check=True, capture_output=True)
    for k, v in (("user.name", "t"), ("user.email", "t@example.invalid"), ("core.autocrlf", "false")):
        git_in(other, "config", k, v)
    (other / "f.txt").write_text("theirs\n", newline="\n")
    git_in(other, "commit", "-qam", "theirs")
    git_in(other, "push", "-q", "origin", "main")
    (clone / "f.txt").write_text("mine\n", newline="\n")
    git_in(clone, "commit", "-qam", "heal")
    r = run_push(clone)
    assert r.returncode != 0 and "Could not rebase" in r.stdout + r.stderr
    assert not (clone / ".git" / "rebase-merge").exists()


@needs_bash
def test_push_script_requires_token(pushrepo):
    _, clone = pushrepo
    assert run_push(clone, token=None).returncode != 0
