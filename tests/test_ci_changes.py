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
