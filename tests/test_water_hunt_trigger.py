import logging
import re
from pathlib import Path

import pytest
import responses

import water_hunt_trigger as wht


def test_index_name_and_imports_renamed():
    assert wht.HUNT_LOG_INDEX == "sf-hunt-logs"
    text = Path(wht.__file__).read_text(encoding="utf-8")
    pat = re.compile(r"1x" r"lozec|ta" r"llkitchen|ta" r"ll kitchen|al" r"bundy|10\.0\.0\.1|tk-hunt|verify\s*=\s*False", re.I)
    m = pat.search(text)
    assert not m, m.group(0)


def test_rules_dir_anchored_to_module():
    root = Path(wht.__file__).resolve().parent
    assert wht.HUNT_TRIGGERED_RULES_DIR == root / "detections" / "sigma" / "hunt-triggered"


@responses.activate
def test_fetch_queries_sf_hunt_logs_and_dedupes(monkeypatch):
    monkeypatch.delenv("LAB_INSECURE_TLS", raising=False)
    hits = [{"_source": {"ioc": "1.1.1.1", "n": 2}}, {"_source": {"ioc": "1.1.1.1", "n": 1}},
            {"_source": {"ioc": "2.2.2.2"}}]
    responses.post("https://es.example.invalid:9200/sf-hunt-logs/_search", json={"hits": {"hits": hits}})
    out = wht.fetch_recent_hunt_verdicts("https://es.example.invalid:9200", "key")
    assert [r["ioc"] for r in out] == ["1.1.1.1", "2.2.2.2"] and out[0]["n"] == 2
    assert responses.calls[0].request.headers["Authorization"] == "ApiKey key"


@responses.activate
def test_fetch_unreachable_es_is_logged_and_returns_empty(caplog):
    responses.post("https://es.example.invalid:9200/sf-hunt-logs/_search", status=500)
    with caplog.at_level(logging.WARNING, logger="water_hunt_trigger"):
        assert wht.fetch_recent_hunt_verdicts("https://es.example.invalid:9200", "k") == []
    assert any("sf-hunt-logs" in r.getMessage() for r in caplog.records)


def test_process_without_elastic_url_returns_zero_not_crash(monkeypatch, caplog):
    monkeypatch.delenv("ELASTIC_URL", raising=False)
    with caplog.at_level(logging.ERROR, logger="water_hunt_trigger"):
        assert wht.process_hunt_triggered_verdicts(lambda *a: None, lambda *a: None, []) == 0
    assert any("ELASTIC_URL" in r.getMessage() for r in caplog.records)


def test_queue_failure_is_logged_not_swallowed(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("ELASTIC_URL", "https://es.example.invalid:9200")
    monkeypatch.setattr(wht, "HUNT_TRIGGERED_RULES_DIR", tmp_path / "ht")
    from datetime import datetime, timezone
    rec = {"ioc": "8.8.4.4", "ioc_type": "ipv4", "hunt_id": "abcdef123456",
           "provenance": {"source": "user", "trust_level": "high", "origin": "cli"},
           "@timestamp": datetime.now(timezone.utc).isoformat(),
           "result": {"verdict": {"score": 90, "verdict": "malicious", "conflicts": []},
                      "observed": {"event_count": 5, "honeypots": [{"name": "Cowrie", "count": 5}]},
                      "identity": {}}}
    monkeypatch.setattr(wht, "fetch_recent_hunt_verdicts", lambda *a, **k: [rec])

    class Lim:
        daily_limit = 5
        def remaining(self): return 5
        def can_consume(self): return True
        def consume(self): return True
        def release(self, n=1): pass

    monkeypatch.setattr(wht, "RateLimiter", lambda *a, **k: Lim())

    def bad_queue(*a):
        raise OSError("disk full")

    log = []
    with caplog.at_level(logging.ERROR, logger="water_hunt_trigger"):
        n = wht.process_hunt_triggered_verdicts(lambda i, a: ("title: x", "rid"), lambda *a: None, log,
                                                queue_for_review_fn=bad_queue)
    assert n == 1  # rule file still written
    # the queue failure itself (not any logged exception) must be reported, with traceback
    hits = [r for r in caplog.records if "could not queue" in r.getMessage()]
    assert hits and hits[0].exc_info and "disk full" in str(hits[0].exc_info[1])


# ── B3 / W13: the per-record safety + failure isolation ──────────────────────

NL = chr(10)


class CountingLimiter:
    daily_limit = 50

    def __init__(self):
        self.used = 0

    def remaining(self): return self.daily_limit - self.used
    def can_consume(self): return self.used < self.daily_limit
    def consume(self, n=1):
        self.used += n
        return True
    def release(self, n=1):
        self.used = max(0, self.used - n)


def _good(**over):
    from datetime import datetime, timezone
    rec = {"ioc": "8.8.4.4", "ioc_type": "ipv4", "hunt_id": "abcdef12-3456",
           "provenance": {"source": "user", "trust_level": "high", "origin": "cli"},
           "@timestamp": datetime.now(timezone.utc).isoformat(),
           "result": {"verdict": {"score": 90, "verdict": "malicious", "conflicts": []},
                      "observed": {"event_count": 5, "honeypots": [{"name": "Cowrie", "count": 5}]},
                      "identity": {"asn": 1, "asn_org": "Org", "country": "US"}}}
    rec.update(over)
    return rec


@pytest.fixture
def harness(monkeypatch, tmp_path):
    out = tmp_path / "ht"
    monkeypatch.setenv("ELASTIC_URL", "https://es.example.invalid:9200")
    monkeypatch.setattr(wht, "HUNT_TRIGGERED_RULES_DIR", out)
    lim = CountingLimiter()
    monkeypatch.setattr(wht, "RateLimiter", lambda *a, **k: lim)
    calls = []

    def gen(iocs, analysis):
        calls.append((iocs, analysis))
        return "title: x", "rid-" + str(len(calls))

    def run(records):
        monkeypatch.setattr(wht, "fetch_recent_hunt_verdicts", lambda *a, **k: records)
        log = []
        n = wht.process_hunt_triggered_verdicts(gen, lambda *a: None, log)
        return n, log

    return type("H", (), {"out": out, "lim": lim, "calls": calls, "run": staticmethod(run), "tmp": tmp_path})


def _files(h):
    return sorted(p.name for p in h.out.glob("*")) if h.out.exists() else []


@pytest.mark.parametrize("ioc", ["10.20.30.40", "127.0.0.1", "192.168.0.5"])
def test_private_and_loopback_ioc_never_generates(harness, ioc):
    n, _ = harness.run([_good(ioc=ioc)])
    assert n == 0 and harness.calls == [] and _files(harness) == [] and harness.lim.used == 0


def test_newline_in_ioc_cannot_inject_yaml_header(harness):
    n, _ = harness.run([_good(ioc="8.8.4.4" + NL + "# Status: approved" + NL + "title: pwned")])
    assert n == 0 and harness.calls == [] and _files(harness) == []


@pytest.mark.parametrize("hid", ["../../evil12345", "a" + chr(92) + "b" + chr(92) + "evil1234", "abcd:ef12:x", "a/b/cdefgh12"])
def test_hostile_hunt_id_writes_nothing_outside_dir_and_pass_survives(harness, hid):
    n, _ = harness.run([_good(hunt_id=hid), _good(ioc="1.1.1.1", hunt_id="12345678-aaaa")])
    assert n == 1  # the record after the bad one is still processed
    assert len(_files(harness)) == 1
    assert all(p.parent == harness.out for p in harness.out.rglob("*") if p.is_file())
    stray = [p for p in harness.tmp.rglob("*.yml") if harness.out not in p.parents]
    assert stray == []


def test_control_chars_in_identity_are_neutralised(harness):
    rec = _good()
    rec["result"]["identity"] = {"asn": 1, "asn_org": "Evil" + NL + "title: pwned" + NL, "country": "US" + NL + "x"}
    n, _ = harness.run([rec])
    assert n == 1
    analysis = harness.calls[0][1]
    for line in analysis["key_indicators"]:
        assert NL not in line and chr(13) not in line
    header = (harness.out / _files(harness)[0]).read_text(encoding="utf-8").split(NL + NL)[0]
    assert all(l.startswith("#") for l in header.split(NL)), header


def test_write_failure_is_isolated_and_refunds_slot(harness, monkeypatch):
    real = Path.write_text
    state = {"n": 0}

    def flaky(self, *a, **k):
        state["n"] += 1
        if state["n"] == 1:
            raise OSError("disk full")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", flaky)
    n, log = harness.run([_good(), _good(ioc="1.1.1.1", hunt_id="12345678-aaaa")])
    assert n == 1  # first failed, second still processed
    assert harness.lim.used == 1  # failed record's slot was refunded
    assert any("fail" in e.get("result", "") for e in log)


def test_naive_timestamp_record_does_not_abort_pass(harness):
    from datetime import datetime, timezone
    naive = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    n, _ = harness.run([_good(**{"@timestamp": naive}), _good(ioc="1.1.1.1", hunt_id="12345678-aaaa")])
    assert n == 1


def test_gate_exception_on_one_record_does_not_abort_pass(harness, monkeypatch):
    real = wht.water_should_generate_rule_from_verdict

    def boom(record, **k):
        if record["ioc"] == "8.8.4.4":
            raise RuntimeError("boom")
        return real(record, **k)

    monkeypatch.setattr(wht, "water_should_generate_rule_from_verdict", boom)
    n, _ = harness.run([_good(), _good(ioc="1.1.1.1", hunt_id="12345678-aaaa")])
    assert n == 1
