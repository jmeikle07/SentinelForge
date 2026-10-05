"""Real multi-process tests for lab.state (threads hide the file lock behind the in-process RLock)."""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from lab import state

ROOT = Path(__file__).resolve().parent.parent

_GO = """
import os, sys, time
def wait_go(flag):
    while not os.path.exists(flag):
        time.sleep(0.001)
"""

_INCREMENT = _GO + """
from lab import state
path, m, go = sys.argv[1], int(sys.argv[2]), sys.argv[3]
wait_go(go)
for _ in range(m):
    state.update(path, lambda v: v + 1, default=0)
"""

# Control: the same workload as a NAIVE read-modify-write (no shared lock hold). It must lose
# updates, which proves the harness really produces contention and can detect a broken lock.
_NAIVE_INCREMENT = _GO + """
import json
from lab import state
path, m, go = sys.argv[1], int(sys.argv[2]), sys.argv[3]
wait_go(go)
for _ in range(m):
    v = state.read(path, default=0)
    time.sleep(0.002)
    state.write(path, v + 1)
"""

_HOLD = """
import sys, time
from lab import state
path, flag = sys.argv[1], sys.argv[2]
def hold(v):
    open(flag, "w").write("held")
    time.sleep(60)
    return v
state.update(path, hold, default=0)
"""


def _spawn(code, *args):
    return subprocess.Popen([sys.executable, "-c", code, *map(str, args)], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _run_workload(code, p, tmp_path, n, m):
    go = tmp_path / "go"
    procs = [_spawn(code, p, m, go) for _ in range(n)]
    time.sleep(1.0)  # let every child import and park at the start barrier
    go.write_text("go")
    for pr in procs:
        _, err = pr.communicate(timeout=180)
        assert pr.returncode == 0, err
    return state.read(p)


def test_n_processes_m_increments_lose_nothing(tmp_path):
    n, m = 5, 25
    assert _run_workload(_INCREMENT, tmp_path / "counter.json", tmp_path, n, m) == n * m


def test_control_naive_read_modify_write_loses_updates(tmp_path):
    n, m = 4, 15
    assert _run_workload(_NAIVE_INCREMENT, tmp_path / "counter.json", tmp_path, n, m) < n * m


def test_killed_holder_does_not_block_others(tmp_path, monkeypatch):
    p = tmp_path / "counter.json"
    flag = tmp_path / "flag"
    holder = _spawn(_HOLD, p, flag)
    try:
        deadline = time.monotonic() + 30
        while not flag.exists():
            assert time.monotonic() < deadline, "holder never took the lock"
            time.sleep(0.05)
        monkeypatch.setattr(state, "LOCK_TIMEOUT", 0.3)
        with pytest.raises(TimeoutError):  # the lock really is held before the kill
            state.update(p, lambda v: v + 1, default=0)
        monkeypatch.setattr(state, "LOCK_TIMEOUT", 10.0)
        holder.kill()
        holder.wait(timeout=10)
        t0 = time.monotonic()
        assert state.update(p, lambda v: v + 1, default=0) == 1
        assert time.monotonic() - t0 < 5
    finally:
        holder.kill()
        holder.communicate()


def test_leftover_lock_file_never_blocks(tmp_path):
    """A lock file left by a crashed process (fresh mtime) must not block: the OS lock is gone."""
    p = tmp_path / "s.json"
    (tmp_path / "s.json.lock").write_text("")
    t0 = time.monotonic()
    state.write(p, {"a": 1})
    assert state.read(p) == {"a": 1}
    assert time.monotonic() - t0 < 2


def test_live_holder_blocks_then_times_out(tmp_path, monkeypatch):
    p = tmp_path / "counter.json"
    flag = tmp_path / "flag"
    holder = _spawn(_HOLD, p, flag)
    try:
        deadline = time.monotonic() + 30
        while not flag.exists():
            assert time.monotonic() < deadline
            time.sleep(0.05)
        monkeypatch.setattr(state, "LOCK_TIMEOUT", 0.5)
        with pytest.raises(TimeoutError):
            state.write(p, 5)
    finally:
        holder.kill()
        holder.communicate()


def test_second_corrupt_file_keeps_first_quarantine(tmp_path):
    p = tmp_path / "s.json"
    p.write_text("{first", encoding="utf-8")
    with pytest.raises(state.StateCorrupt):
        state.read(p)
    p.write_text("{second", encoding="utf-8")
    with pytest.raises(state.StateCorrupt):
        state.read(p)
    kept = sorted(f for f in tmp_path.iterdir() if ".corrupt" in f.name)
    assert len(kept) == 2
    assert {f.read_text(encoding="utf-8") for f in kept} == {"{first", "{second"}
    assert (tmp_path / "s.corrupt").read_text(encoding="utf-8") == "{first"  # sf_web looks here


def test_update_is_one_hold_and_atomic_on_failure(tmp_path):
    p = tmp_path / "s.json"
    assert state.update(p, lambda v: v + [1], default=[]) == [1]
    with pytest.raises(ValueError):
        state.update(p, lambda v: (_ for _ in ()).throw(ValueError("boom")), default=[])
    assert json.loads(p.read_text()) == [1]
    # missing file without default: FileNotFoundError, nothing created
    with pytest.raises(FileNotFoundError):
        state.update(tmp_path / "none.json", lambda v: v)
    assert not (tmp_path / "none.json").exists()
