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
    rec = {"ioc": "203.0.113.9", "ioc_type": "ipv4", "hunt_id": "abcdef123456",
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

    monkeypatch.setattr(wht, "RateLimiter", lambda *a, **k: Lim())

    def bad_queue(*a):
        raise OSError("disk full")

    log = []
    with caplog.at_level(logging.ERROR, logger="water_hunt_trigger"):
        n = wht.process_hunt_triggered_verdicts(lambda i, a: ("title: x", "rid"), lambda *a: None, log,
                                                queue_for_review_fn=bad_queue)
    assert n == 1  # rule file still written
    assert any("disk full" in r.getMessage() or r.exc_info for r in caplog.records)
