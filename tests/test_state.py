import json
import threading

import pytest

from lab import state


def test_state_write_is_atomic_and_corrupt_file_raises(tmp_path):
    p = tmp_path / "s.json"
    state.write(p, [1, 2, 3])
    assert state.read(p) == [1, 2, 3]
    assert sorted(f.name for f in tmp_path.iterdir() if f.suffix != ".lock") == ["s.json"]  # no temp leftovers

    p.write_text('{"half": ', encoding="utf-8")
    with pytest.raises(state.StateCorrupt):
        state.read(p)
    assert (tmp_path / "s.corrupt").exists()
    assert not p.exists()


def test_write_failure_keeps_old_file(tmp_path):
    p = tmp_path / "s.json"
    state.write(p, {"a": 1})

    with pytest.raises(TypeError):
        state.write(p, {"a": object()})  # not JSON serializable
    assert json.loads(p.read_text()) == {"a": 1}
    assert sorted(f.name for f in tmp_path.iterdir() if f.suffix != ".lock") == ["s.json"]


def test_read_missing_raises_or_default(tmp_path):
    with pytest.raises(FileNotFoundError):
        state.read(tmp_path / "nope.json")
    assert state.read(tmp_path / "nope.json", default=[]) == []


def test_concurrent_writes_never_corrupt(tmp_path):
    p = tmp_path / "s.json"
    errs = []

    def w(i):
        try:
            for _ in range(20):
                state.write(p, {"i": i, "pad": "x" * 1000})
        except Exception as e:  # noqa: BLE001
            errs.append(e)

    ts = [threading.Thread(target=w, args=(i,)) for i in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert errs == []
    assert state.read(p)["pad"] == "x" * 1000


def test_update_does_not_mutate_callers_default(tmp_path):
    shared = []

    def add(v):
        v.append(1)
        return v

    assert state.update(tmp_path / "a.json", add, default=shared) == [1]
    assert shared == []  # the caller's default object is never handed to fn
    assert state.update(tmp_path / "b.json", add, default=shared) == [1]


def test_update_corrupt_file_quarantined_even_with_default(tmp_path):
    p = tmp_path / "s.json"
    p.write_text("{bad", encoding="utf-8")
    with pytest.raises(state.StateCorrupt):
        state.update(p, lambda v: v, default={})
    assert not p.exists() and (tmp_path / "s.corrupt").exists()


def test_lock_wait_on_unrelated_file_honors_timeout(tmp_path):
    """File locks are serialized in-process by one thread lock; waiting for it must still time out."""
    started, release = threading.Event(), threading.Event()

    def holder():
        with state.file_lock(tmp_path / "x.lock"):
            started.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    assert started.wait(5)
    try:
        import time
        t0 = time.monotonic()
        with pytest.raises(TimeoutError):
            with state.file_lock(tmp_path / "y.lock", timeout=0.3):
                pass
        assert time.monotonic() - t0 < 2
    finally:
        release.set()
        t.join()


def test_opposite_nested_lock_order_in_two_threads_does_not_deadlock(tmp_path):
    """Documented ordering guarantee: in-process, file locks are serialized by one thread lock,
    so thread A (X then Y) and thread B (Y then X) cannot deadlock."""
    x, y = tmp_path / "x.json", tmp_path / "y.json"
    errs = []

    def a():
        try:
            for _ in range(20):
                with state._locked(x):
                    state.update(y, lambda v: v + 1, default=0)
        except Exception as e:  # noqa: BLE001
            errs.append(e)

    def b():
        try:
            for _ in range(20):
                with state._locked(y):
                    state.update(x, lambda v: v + 1, default=0)
        except Exception as e:  # noqa: BLE001
            errs.append(e)

    ts = [threading.Thread(target=a), threading.Thread(target=b)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    assert errs == [] and not any(t.is_alive() for t in ts)
    assert state.read(x) == 20 and state.read(y) == 20


def test_reentrant_lock_in_same_thread(tmp_path):
    p = tmp_path / "s.json"
    with state._locked(p):
        state.write(p, 1)
        assert state.update(p, lambda v: v + 1, default=0) == 2
        assert state.read(p) == 2


class _FakeFcntl:
    LOCK_EX, LOCK_NB, LOCK_UN = 2, 4, 8

    def __init__(self, busy_first=0):
        self.calls, self.busy = [], busy_first

    def flock(self, fd, op):
        self.calls.append(op)
        if op & self.LOCK_NB and self.busy:
            self.busy -= 1
            raise BlockingIOError("busy")


def test_posix_branch_flock_control_flow(tmp_path, monkeypatch):
    fake = _FakeFcntl(busy_first=2)
    monkeypatch.setattr(state, "_msvcrt", None)
    monkeypatch.setattr(state, "_fcntl", fake, raising=False)
    with state.file_lock(tmp_path / "l.lock"):
        assert fake.calls == [6, 6, 6]  # EX|NB retried twice, then acquired
        with state.file_lock(tmp_path / "l.lock"):  # re-entrant: no further flock
            assert len(fake.calls) == 3
    assert fake.calls[-1] == fake.LOCK_UN


def test_posix_branch_times_out_and_unlocks_on_error(tmp_path, monkeypatch):
    fake = _FakeFcntl(busy_first=10**9)
    monkeypatch.setattr(state, "_msvcrt", None)
    monkeypatch.setattr(state, "_fcntl", fake, raising=False)
    with pytest.raises(TimeoutError):
        with state.file_lock(tmp_path / "l.lock", timeout=0.05):
            pass
    fake2 = _FakeFcntl()
    monkeypatch.setattr(state, "_fcntl", fake2, raising=False)
    with pytest.raises(ValueError):
        with state.file_lock(tmp_path / "l.lock"):
            raise ValueError("x")
    assert fake2.calls[-1] == fake2.LOCK_UN
    with state.file_lock(tmp_path / "l.lock"):  # held-set was cleaned up
        pass
