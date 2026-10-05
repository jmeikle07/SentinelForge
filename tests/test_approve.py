import json
import subprocess
import sys
from pathlib import Path

import pytest

import approve

ROOT = Path(__file__).resolve().parent.parent
RID = "aaaaaaaa-1111-2222-3333-444444444444"


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
