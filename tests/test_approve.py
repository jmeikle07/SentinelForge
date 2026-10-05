import copy
import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import approve
import generate_rule as gr

ROOT = Path(__file__).resolve().parent.parent
RID = "aaaaaaaa-1111-2222-3333-444444444444"
RID2 = "bbbbbbbb-1111-2222-3333-444444444444"


def test_approve_does_not_import_generate_rule_at_import_time():
    code = "import sys, approve; sys.exit(1 if 'generate_rule' in sys.modules else 0)"
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr


@pytest.fixture
def queue(tmp_path, monkeypatch):
    state = tmp_path / "state" / "pending_rules.json"
    pend = tmp_path / "pending"
    pend.mkdir()
    monkeypatch.setattr(approve, "STATE", state)
    monkeypatch.setattr(approve, "PENDING_DIR", pend)
    state.parent.mkdir()
    state.write_text(json.dumps([{"rule_id": RID, "technique_id": "T1059",
                                  "technique_name": "Cmd", "tactic": "execution"}]))
    (pend / f"{RID}.yml").write_text("title: x\n")
    return state, pend


def test_reject_removes_entry_and_yaml(queue):
    state, pend = queue
    approve.cmd_reject("aaaaaaaa")
    assert json.loads(state.read_text()) == []
    assert not (pend / f"{RID}.yml").exists()


@pytest.mark.parametrize("bad", ["../x", "..\\x", "a/b", "zz", "", "x" * 40])
def test_prefix_with_non_uuid_characters_is_rejected(queue, bad):
    with pytest.raises(SystemExit) as ei:
        approve.cmd_show(bad)
    assert ei.value.code == 1


def test_corrupt_pending_file_is_quarantined_not_overwritten(queue):
    state, _ = queue
    state.write_text("{not json")
    with pytest.raises(SystemExit) as ei:
        approve.cmd_list()
    assert ei.value.code == 1
    assert state.with_suffix(".corrupt").exists()
    assert not state.exists()  # never silently replaced with []


# ------------------------------------------------------------------ publish-first approve
_RULE = {
    "title": "Encoded PowerShell Command", "id": RID, "status": "experimental",
    "description": "Detects encoded PowerShell.", "author": "Tester", "date": "2026/10/05",
    "tags": ["attack.execution", "attack.t1059.001"],
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {"selection": {"process.name|endswith": "powershell.exe",
                                "process.command_line|contains": ["-enc"]},
                  "condition": "selection"},
    "level": "high",
}


def _yaml(rid=RID, **over):
    d = copy.deepcopy(_RULE)
    d.update(over, id=rid)
    return gr.render_rule(d)


def _entry(rid=RID, **over):
    e = {"rule_id": rid, "technique_id": "T1059.001", "technique_name": "PowerShell",
         "tactic": "execution", "confidence": "high", "queued_at": "2026-10-05T00:00:00+00:00"}
    e.update(over)
    return e


class FakeGit:
    def __init__(self):
        self.calls, self.fail_on = [], None

    def __call__(self, *args):
        self.calls.append(args)
        if self.fail_on and args[0] == self.fail_on:
            raise gr.GitError(f"git {args[0]} failed: boom")


@pytest.fixture
def env(tmp_path, monkeypatch):
    sdir, pend, sigma = tmp_path / "state", tmp_path / "pending", tmp_path / "sigma"
    sdir.mkdir()
    pend.mkdir()
    sigma.mkdir()
    monkeypatch.setattr(approve, "STATE", sdir / "pending_rules.json")
    monkeypatch.setattr(approve, "PENDING_DIR", pend)
    monkeypatch.setattr(approve, "SIGMA_DIR", sigma)
    git = FakeGit()
    monkeypatch.setattr(gr, "_git", git)
    pushed = []
    monkeypatch.setattr(gr, "git_push_state", lambda: pushed.append(1))
    (sdir / "pending_rules.json").write_text(json.dumps([_entry()]))
    (sdir / "seen_techniques.json").write_text(json.dumps({"T1000": {"rule_id": "old"}}))
    (sdir / "hunt_log.json").write_text(json.dumps([{"result": "old"}]))
    (pend / f"{RID}.yml").write_text(_yaml())
    return SimpleNamespace(sdir=sdir, pend=pend, sigma=sigma, git=git, pushed=pushed,
                           queue=lambda: json.loads((sdir / "pending_rules.json").read_text()))


def test_approve_success_publishes_then_updates_state(env):
    approve.cmd_approve("aaaaaaaa")
    files = list(env.sigma.iterdir())
    assert len(files) == 1 and yaml.safe_load(files[0].read_text())["id"] == RID
    assert [c[0] for c in env.git.calls] == ["add", "commit", "pull", "push"]
    assert env.queue() == []
    assert not (env.pend / f"{RID}.yml").exists()
    seen = json.loads((env.sdir / "seen_techniques.json").read_text())
    assert seen["T1000"] == {"rule_id": "old"} and seen["T1059.001"]["rule_id"] == RID
    log = json.loads((env.sdir / "hunt_log.json").read_text())
    assert log[0] == {"result": "old"} and log[-1]["result"] == "deployed" and log[-1]["rule_id"] == RID
    assert log[-1]["filepath"].endswith(files[0].name)
    assert env.pushed == [1]


@pytest.mark.parametrize("fail_on", ["add", "commit", "push"])
def test_publish_failure_leaves_everything_retryable(env, fail_on, capsys):
    env.git.fail_on = fail_on
    names = ("pending_rules.json", "seen_techniques.json", "hunt_log.json")
    before = {n: (env.sdir / n).read_text() for n in names}
    with pytest.raises(SystemExit) as ei:
        approve.cmd_approve("aaaaaaaa")
    assert ei.value.code not in (0, None)
    assert "boom" in capsys.readouterr().out
    assert {n: (env.sdir / n).read_text() for n in names} == before  # state untouched
    assert (env.pend / f"{RID}.yml").exists()
    assert env.pushed == []
    # retry with a working git: succeeds, exactly one rule file, queue drained
    env.git.fail_on = None
    approve.cmd_approve("aaaaaaaa")
    assert len(list(env.sigma.iterdir())) == 1
    assert env.queue() == [] and not (env.pend / f"{RID}.yml").exists()
    assert env.git.calls[-1][0] == "push"  # a commit that never got pushed is pushed on retry


def test_approve_rejects_yaml_whose_id_differs_from_queue_entry(env):
    (env.pend / f"{RID}.yml").write_text(_yaml(rid=RID2))
    with pytest.raises(SystemExit) as ei:
        approve.cmd_approve("aaaaaaaa")
    assert ei.value.code == 1
    assert list(env.sigma.iterdir()) == [] and env.git.calls == []
    assert env.queue() == [_entry()] and (env.pend / f"{RID}.yml").exists()


def test_approve_rejects_invalid_pending_yaml(env):
    (env.pend / f"{RID}.yml").write_text("title: x\n")
    with pytest.raises(SystemExit) as ei:
        approve.cmd_approve("aaaaaaaa")
    assert ei.value.code == 1 and env.git.calls == [] and env.queue() == [_entry()]


def test_approve_missing_yaml_fails_cleanly(env):
    (env.pend / f"{RID}.yml").unlink()
    with pytest.raises(SystemExit) as ei:
        approve.cmd_approve("aaaaaaaa")
    assert ei.value.code == 1 and env.queue() == [_entry()]


def test_state_push_failure_after_publish_is_reported_but_rule_is_done(env, monkeypatch):
    def boom():
        raise gr.GitError("state push failed")
    monkeypatch.setattr(gr, "git_push_state", boom)
    with pytest.raises(SystemExit) as ei:
        approve.cmd_approve("aaaaaaaa")
    assert ei.value.code not in (0, None)
    assert env.queue() == [] and len(list(env.sigma.iterdir())) == 1


def test_reject_leaves_other_entries_and_state(env):
    env.sdir.joinpath("pending_rules.json").write_text(json.dumps([_entry(), _entry(RID2)]))
    approve.cmd_reject("aaaaaaaa")
    assert [e["rule_id"] for e in env.queue()] == [RID2]
    assert not (env.pend / f"{RID}.yml").exists()
    assert json.loads((env.sdir / "seen_techniques.json").read_text()) == {"T1000": {"rule_id": "old"}}


def test_malformed_queue_items_are_skipped_and_never_dropped(env, capsys):
    junk = ["a string", None, 7, {"technique_id": "T1"}, {"rule_id": 5}, {"rule_id": "../x"},
            {"rule_id": "abcdef"}]
    partial = {"rule_id": RID2}  # valid id, no technique fields
    env.sdir.joinpath("pending_rules.json").write_text(json.dumps(junk + [_entry(), partial]))
    approve.cmd_list()
    out = capsys.readouterr().out
    assert "malformed" in out.lower() and RID[:8] in out
    approve.cmd_approve("aaaaaaaa")
    assert env.queue() == junk + [partial]  # every other entry untouched, order kept
    with pytest.raises(SystemExit) as ei:
        approve.cmd_approve("bbbbbbbb")  # cannot be deployed, but must not crash
    assert ei.value.code == 1
    approve.cmd_reject("bbbbbbbb")
    assert env.queue() == junk


def test_non_list_queue_is_an_error_not_a_crash(env):
    env.sdir.joinpath("pending_rules.json").write_text(json.dumps({"oops": 1}))
    with pytest.raises(SystemExit) as ei:
        approve.cmd_list()
    assert ei.value.code == 1


_APPEND = """
import os, sys, time
from lab import state
path, seen, n, go, tag = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
while not os.path.exists(go):
    time.sleep(0.001)
for i in range(n):  # what generate_rule does: queue append + seen_techniques merge
    rid = "00000000-0000-0000-0000-%012d" % (int(tag) * 1000 + i)
    state.update(path, lambda q: q + [{"rule_id": rid, "technique_id": "T1", "technique_name": "n"}], default=[])
    state.update(seen, lambda s: {**s, "X%s-%d" % (tag, i): {}}, default={})
"""


def test_concurrent_approve_vs_queue_appends_in_other_processes_lose_nothing(env):
    env.sdir.joinpath("pending_rules.json").write_text(json.dumps([_entry(), _entry(RID2)]))
    (env.pend / f"{RID2}.yml").write_text(_yaml(rid=RID2))
    go = env.sdir / "go"
    qpath, spath = env.sdir / "pending_rules.json", env.sdir / "seen_techniques.json"
    procs = [subprocess.Popen([sys.executable, "-c", _APPEND, str(qpath), str(spath), "40", str(go), str(t)],
                              cwd=ROOT, stderr=subprocess.PIPE, text=True) for t in (1, 2, 3)]
    time.sleep(1.0)
    go.write_text("go")
    approve.cmd_approve("aaaaaaaa")
    approve.cmd_reject("bbbbbbbb")
    for p in procs:
        _, err = p.communicate(timeout=120)
        assert p.returncode == 0, err
    ids = [e["rule_id"] for e in env.queue()]
    assert RID not in ids and RID2 not in ids and len(ids) == 120 and len(set(ids)) == 120
    seen = json.loads(spath.read_text())
    assert len(seen) == 1 + 1 + 120 and "T1059.001" in seen  # T1000 + approve + every append
