import json
import threading

import pytest

from lab import state


def test_state_write_is_atomic_and_corrupt_file_raises(tmp_path):
    p = tmp_path / "s.json"
    state.write(p, [1, 2, 3])
    assert state.read(p) == [1, 2, 3]
    assert [f.name for f in tmp_path.iterdir()] == ["s.json"]  # no temp/lock leftovers

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
    assert [f.name for f in tmp_path.iterdir()] == ["s.json"]


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
