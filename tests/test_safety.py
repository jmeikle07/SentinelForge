import json
import os
import subprocess
import sys
import multiprocessing
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
        "ioc": "8.8.4.4", "ioc_type": "ipv4", "hunt_id": "abcdef12-3456",
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


# ── B3: format validation of ioc / hunt_id ───────────────────────────────────

@pytest.mark.parametrize("ioc", ["10.20.30.40", "127.0.0.1", "192.168.1.1", "169.254.1.1", "203.0.113.9",
                                 "8.8.4.4\n# injected", "::1", "2001:4860::8888", "not-an-ip", "08.8.4.4", None, 5])
def test_non_global_or_malformed_ioc_rejected(ioc):
    assert not sf_safety.validate_hunt_record_for_water(_record(ioc=ioc)).passed


@pytest.mark.parametrize("t", ["domain", "sha256", "url", None])
def test_only_ipv4_ioc_type_allowed(t):
    assert not sf_safety.validate_hunt_record_for_water(_record(ioc_type=t)).passed


@pytest.mark.parametrize("hid", ["a/b/../../etc1234", "..\\..\\evil12345", "abcd:ef12:stream", "ABCDEF12", "abc",
                                 "a" * 37, "abcdef12\n", "", None, 12345678])
def test_bad_hunt_id_rejected(hid):
    assert not sf_safety.validate_hunt_record_for_water(_record(hunt_id=hid)).passed


def test_missing_hunt_id_rejected():
    rec = _record()
    del rec["hunt_id"]
    assert not sf_safety.validate_hunt_record_for_water(rec).passed


def test_sanitize_text_strips_control_chars_and_caps():
    raw = "a\nb\r\x00c\u2028d\x1b[31m" + "x" * 500
    out = sf_safety.sanitize_text(raw, max_len=20)
    assert not any(ord(c) < 32 or ord(c) in (0x7f, 0x2028, 0x2029) for c in out)
    assert len(out) <= 20
    assert sf_safety.sanitize_text(None) == ""


# ── W13: robustness of the gate ──────────────────────────────────────────────

def test_naive_timestamp_rejected_cleanly_not_raised():
    naive = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    res = sf_safety.validate_hunt_record_for_water(_record(timestamp_utc=naive))
    assert not res.passed and "timezone" in res.reason


def test_z_suffix_timestamp_still_ok():
    z = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert sf_safety.validate_hunt_record_for_water(_record(timestamp_utc=z)).passed


def test_bool_score_is_not_an_int_score():
    res = sf_safety.validate_hunt_record_for_water(_record(verdict={"score": True, "verdict": "malicious"}))
    assert not res.passed and "numeric" in res.reason
    assert not sf_safety.should_water_act_on_hunt(_record(verdict={"score": True, "verdict": "malicious"})).passed


def test_score_75_boundary():
    ok = _record(verdict={"score": 75, "verdict": "suspicious", "conflicts": []})
    below = _record(verdict={"score": 74.9, "verdict": "suspicious", "conflicts": []})
    assert sf_safety.should_water_act_on_hunt(ok).passed
    assert not sf_safety.should_water_act_on_hunt(below).passed


@pytest.mark.parametrize("conflicts", [[{"a": 1}], [None], [123], "plain string", {"k": "v"}, 7])
def test_non_string_conflicts_do_not_crash(conflicts):
    res = sf_safety.should_water_act_on_hunt(_record(verdict={"score": 90, "verdict": "malicious", "conflicts": conflicts}))
    assert not res.passed and "conflicts" in res.reason


def test_rule_id_none_does_not_crash():
    rule = {"id": None, "title": "Whitelist infra", "tags": [None, "whitelist"], "ip": "8.8.4.4"}
    out = sf_safety.cross_pillar_disagreement_check(_record(), [rule])
    assert len(out) == 1
    res = sf_safety.water_should_generate_rule_from_verdict(_record(), [rule])
    assert not res.passed


# ── W14: atomic rate limiter across processes ────────────────────────────────

def _consume_worker(state_dir, n, start_evt, out_q):
    import sf_safety as sfs
    from pathlib import Path as P
    sfs.SAFETY_STATE_DIR = P(state_dir)
    lim = sfs.RateLimiter("mp", daily_limit=5)
    start_evt.wait()
    out_q.put(sum(1 for _ in range(n) if lim.consume()))


def test_concurrent_processes_cannot_exceed_cap(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    start, q = ctx.Event(), ctx.Queue()
    procs = [ctx.Process(target=_consume_worker, args=(str(tmp_path / "sf"), 6, start, q)) for _ in range(6)]
    for p in procs:
        p.start()
    start.set()
    got = [q.get(timeout=120) for _ in procs]
    for p in procs:
        p.join(timeout=60)
    assert sum(got) == 5, got  # exactly the cap: no lost updates, no over-spend
    lim = sf_safety.RateLimiter.__new__(sf_safety.RateLimiter)
    data = json.loads((tmp_path / "sf" / "ratelimit_mp.json").read_text())
    assert max(data.values()) == 5


def test_release_gives_slot_back(state_dir):
    lim = sf_safety.RateLimiter("r", daily_limit=1)
    assert lim.consume() and not lim.consume()
    lim.release()
    assert lim.consume()
    lim.release(5)  # never goes below zero
    assert lim.current_count() == 0
