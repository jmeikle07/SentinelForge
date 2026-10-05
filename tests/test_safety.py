import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import sf_safety


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(sf_safety, "SAFETY_STATE_DIR", tmp_path / "sf")
    return tmp_path / "sf"


def _record(**over):
    rec = {
        "ioc": "203.0.113.9", "ioc_type": "ipv4",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "verdict": {"score": 90, "verdict": "malicious", "conflicts": []},
        "provenance": {"source": sf_safety.SOURCE_USER, "trust_level": sf_safety.TRUST_LEVEL_HIGH},
    }
    rec.update(over)
    return rec


def test_state_dir_is_anchored_to_module_not_cwd(tmp_path):
    code = "import sf_safety; print(sf_safety.SAFETY_STATE_DIR)"
    root = Path(sf_safety.__file__).resolve().parent
    env = dict(os.environ, PYTHONPATH=str(root))
    out = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env,
                         capture_output=True, text=True, check=True).stdout.strip()
    assert Path(out).is_absolute()
    assert Path(out) == root / "state" / "sf"


def test_good_record_passes_and_water_source_is_refused():
    assert sf_safety.should_water_act_on_hunt(_record()).passed
    water = _record(provenance={"source": sf_safety.SOURCE_WATER, "trust_level": "high"})
    res = sf_safety.should_water_act_on_hunt(water)
    assert not res.passed and "feedback loop" in res.reason


def test_low_score_conflicts_and_safety_brake_refused():
    low = _record(verdict={"score": 60, "verdict": "suspicious", "conflicts": []})
    assert not sf_safety.should_water_act_on_hunt(low).passed
    conflicted = _record(verdict={"score": 90, "verdict": "malicious", "conflicts": ["x vs y"]})
    assert not sf_safety.should_water_act_on_hunt(conflicted).passed
    braked = _record(verdict={"score": 80, "verdict": "malicious", "conflicts": [], "safety_brake": True})
    assert not sf_safety.should_water_act_on_hunt(braked).passed


def test_rate_limiter_persists_and_caps(state_dir):
    lim = sf_safety.RateLimiter("t", daily_limit=2)
    assert lim.consume() and lim.consume() and not lim.consume()
    again = sf_safety.RateLimiter("t", daily_limit=2)  # new process analogue
    assert again.remaining() == 0 and not again.can_consume()
    assert json.loads((state_dir / "ratelimit_t.json").read_text())  # real JSON on disk


def test_rate_limiter_corrupt_state_is_quarantined_and_logged(state_dir, caplog):
    lim = sf_safety.RateLimiter("t", daily_limit=2)
    lim.state_file.write_text("{not json", encoding="utf-8")
    with caplog.at_level("ERROR"):
        assert lim.current_count() == 0  # does not crash
    assert lim.state_file.with_suffix(".corrupt").exists()  # evidence preserved, not overwritten
    assert any("corrupt" in r.message.lower() for r in caplog.records)


def test_no_legacy_strings_in_safety_module():
    text = Path(sf_safety.__file__).read_text(encoding="utf-8").lower()
    for bad in ("ta" "llkitchen", "tk-hunt", "1x" "lozec"):
        assert bad not in text
