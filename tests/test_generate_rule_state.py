"""generate_rule's writes to shared state files must merge with concurrent writers (approve.py,
another engine run) instead of overwriting them."""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

import generate_rule as gr
from lab import state as lab_state

ROOT = Path(__file__).resolve().parent.parent
ANALYSIS = {"technique_id": "T1059", "technique_name": "Command Interpreter", "tactic": "execution",
            "confidence": "high"}


@pytest.fixture
def sdir(tmp_path, monkeypatch):
    d = tmp_path / "state"
    d.mkdir()
    monkeypatch.setattr(gr, "STATE_DIR", d)
    monkeypatch.setattr(gr, "HERE", tmp_path)
    monkeypatch.setattr(gr, "write_ai_context", lambda a: "ctx")
    (d / "seen_techniques.json").write_text(json.dumps({"T1": {"rule_id": "r1"}}))
    (d / "hunt_log.json").write_text(json.dumps([{"result": "old"}]))
    (d / "last_run.json").write_text(json.dumps({"timestamp": "t0"}))
    (d / "weekly_digest.json").write_text(json.dumps({"week_start": None}))
    return d


def _read(d, name):
    return json.loads((d / name).read_text())


def test_save_state_keeps_updates_made_by_another_writer_after_load(sdir):
    seen, last, log, digest = gr.load_state()
    # the engine run works on its in-memory copy ...
    seen["T2"] = {"rule_id": "mine"}
    log.append({"result": "mine"})
    last["timestamp"] = "t1"
    digest["week_start"] = "w1"
    # ... while approve.py (any other writer) commits to the same files
    lab_state.update(sdir / "seen_techniques.json", lambda s: {**s, "T3": {"rule_id": "theirs"}}, default={})
    lab_state.update(sdir / "hunt_log.json", lambda l: l + [{"result": "theirs"}], default=[])
    gr.save_state(seen, last, log, digest)
    assert set(_read(sdir, "seen_techniques.json")) == {"T1", "T2", "T3"}
    assert [e["result"] for e in _read(sdir, "hunt_log.json")] == ["old", "theirs", "mine"]
    assert _read(sdir, "last_run.json") == {"timestamp": "t1"}
    assert _read(sdir, "weekly_digest.json") == {"week_start": "w1"}


def test_repeated_save_state_appends_each_log_entry_once(sdir):
    seen, last, log, digest = gr.load_state()
    log.append({"result": "a"})
    gr.save_state(seen, last, log, digest)
    log.append({"result": "b"})
    gr.save_state(seen, last, log, digest)
    gr.save_state(seen, last, log, digest)
    assert [e["result"] for e in _read(sdir, "hunt_log.json")] == ["old", "a", "b"]


def test_save_state_without_load_still_writes_everything(sdir):
    gr._BASE.clear()
    gr.save_state({"T9": {}}, {"timestamp": "x"}, [{"a": 1}], {"week_start": None})
    assert _read(sdir, "seen_techniques.json") == {"T9": {}}
    assert _read(sdir, "hunt_log.json") == [{"a": 1}]


def test_queue_for_review_does_not_lose_entry_appended_mid_call(sdir, monkeypatch):
    pfile = sdir / "pending_rules.json"
    calls = []

    def ctx(analysis):  # a concurrent writer lands while queue_for_review is working
        if not calls:
            calls.append(1)
            lab_state.update(pfile, lambda q: q + [{"rule_id": "other"}], default=[])
        return "ctx"

    monkeypatch.setattr(gr, "write_ai_context", ctx)
    gr.queue_for_review("title: x\n", ANALYSIS, "rid-1", "now")
    assert sorted(i["rule_id"] for i in _read(sdir, "pending_rules.json")) == ["other", "rid-1"]


def test_queue_failed_appends_and_refuses_a_non_list_file(sdir):
    path = sdir / "failed_rules.json"
    gr.queue_failed("generation", "raw", "err", "t1")
    gr.queue_failed("analysis", "raw", "err", "t2")
    assert [i["stage"] for i in _read(sdir, "failed_rules.json")] == ["generation", "analysis"]
    path.write_text(json.dumps({"oops": 1}))
    with pytest.raises(ValueError):
        gr.queue_failed("generation", "raw", "err", "t3")
    assert json.loads(path.read_text()) == {"oops": 1}  # untouched


_WRITER = """
import os, sys, time
from lab import state
q, f, go, tag, n = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
while not os.path.exists(go):
    time.sleep(0.001)
for i in range(n):
    state.update(q, lambda v: v + [{"rule_id": "w%s-%d" % (tag, i)}], default=[])
    state.update(f, lambda v: v + [{"stage": "w%s-%d" % (tag, i)}], default=[])
"""


def test_queue_writes_in_this_process_vs_other_processes_lose_nothing(sdir):
    q, f, go = sdir / "pending_rules.json", sdir / "failed_rules.json", sdir / "go"
    procs = [subprocess.Popen([sys.executable, "-c", _WRITER, str(q), str(f), str(go), str(t), "25"],
                              cwd=ROOT, stderr=subprocess.PIPE, text=True) for t in (1, 2)]
    time.sleep(1.0)
    go.write_text("go")
    for i in range(25):
        gr.queue_for_review("title: x\n", ANALYSIS, "mine-%d" % i, "now")
        gr.queue_failed("generation", "raw", "err", "now")
    for p in procs:
        _, err = p.communicate(timeout=120)
        assert p.returncode == 0, err
    assert len(_read(sdir, "pending_rules.json")) == 75
    assert len(_read(sdir, "failed_rules.json")) == 75
