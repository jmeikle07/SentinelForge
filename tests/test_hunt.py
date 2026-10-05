import logging
import re
import threading
import time
from pathlib import Path

import pytest
import requests
import responses

import sf_hunt

IP_SOURCES = {
    "abuseipdb": "abuseipdb_check_ip",
    "greynoise": "greynoise_check_ip",
    "virustotal": "virustotal_check_ip",
    "otx": "otx_check_ip",
    "internetdb": "internetdb_check_ip",
    "spamhaus_drop": "spamhaus_drop_check_ip",
}


@pytest.fixture
def mem(tmp_path, monkeypatch):
    monkeypatch.setattr(sf_hunt, "MEMORY_DIR", tmp_path)
    monkeypatch.setattr(sf_hunt, "MEMORY_DB", tmp_path / "m.db")
    conn = sf_hunt.memory_init()
    yield conn
    conn.close()


def _fake_all(monkeypatch, delay=0.0, fail=None):
    def make(name):
        def fake(conn, ip, *a):
            time.sleep(delay)
            if name == fail:
                raise RuntimeError("boom " + name)
            return {"available": True, "src": name}
        return fake
    for name, fn in IP_SOURCES.items():
        monkeypatch.setattr(sf_hunt, fn, make(name))
    monkeypatch.setattr(sf_hunt, "threatfox_check_ioc", make("threatfox"))


def test_bucket_external_ip_queries_sources_in_parallel(monkeypatch):
    _fake_all(monkeypatch, delay=0.3)
    start = time.monotonic()
    out = sf_hunt.bucket_external_ip(None, "203.0.113.9")
    elapsed = time.monotonic() - start
    assert set(out) == set(IP_SOURCES) | {"threatfox"}
    assert elapsed < 0.3 * 7 * 0.6  # 7 sources, well under the serial sum (2.1s)


def test_bucket_external_hash_and_domain_run_in_parallel(monkeypatch):
    def slow(name):
        def f(conn, *a):
            time.sleep(0.3)
            return {"available": True, "src": name}
        return f
    for fn in ("malwarebazaar_check_hash", "virustotal_check_hash", "otx_check_hash"):
        monkeypatch.setattr(sf_hunt, fn, slow(fn))
    monkeypatch.setattr(sf_hunt, "threatfox_check_ioc", slow("tf"))
    start = time.monotonic()
    out = sf_hunt.bucket_external_hash(None, "a" * 64, "sha256")
    assert time.monotonic() - start < 0.3 * 4 * 0.7
    assert set(out) == {"malwarebazaar", "virustotal", "otx", "threatfox"}


def test_source_failure_is_logged_and_scored_unknown_not_swallowed(monkeypatch, caplog):
    _fake_all(monkeypatch, fail="virustotal")
    with caplog.at_level(logging.WARNING, logger="sf_hunt"):
        out = sf_hunt.bucket_external_ip(None, "203.0.113.9")
    assert out["virustotal"]["available"] is False
    assert "RuntimeError" in out["virustotal"]["reason"]
    assert out["abuseipdb"]["available"] is True  # isolated: the others still answered
    assert any("virustotal" in r.getMessage() and r.levelno >= logging.WARNING for r in caplog.records)
    verdict = sf_hunt.bucket_verdict({}, out, "ipv4")
    assert verdict["signals"]["virustotal"] == 0.0  # unknown contributes nothing


def test_malwarebazaar_ttl_is_24h():
    assert sf_hunt.CACHE_TTL_SECONDS["malwarebazaar"] == 24 * 3600


def test_cache_roundtrip_is_thread_safe(mem):
    errors = []

    def work(i):
        try:
            for j in range(20):
                sf_hunt.cache_put(mem, f"ioc{i}", "otx", {"n": j})
                assert sf_hunt.cache_get(mem, f"ioc{i}", "otx") == {"n": j}
        except Exception as e:  # noqa: BLE001 - collected for the assertion below
            errors.append(e)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors


def test_cache_get_corrupt_row_is_logged_and_treated_as_miss(mem, caplog):
    mem.execute("INSERT INTO enrichment_cache VALUES ('1.2.3.4','otx',?, '{bad', 200)",
                (time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),))
    mem.commit()
    with caplog.at_level(logging.WARNING, logger="sf_hunt"):
        assert sf_hunt.cache_get(mem, "1.2.3.4", "otx") is None
    assert any("otx" in r.getMessage() for r in caplog.records)


@responses.activate
def test_elk_search_uses_configured_url_and_tls_verification(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://es.example.invalid:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "k")
    monkeypatch.delenv("LAB_INSECURE_TLS", raising=False)
    responses.post("https://es.example.invalid:9200/tpot-*/_search", json={"hits": {"hits": []}})
    assert sf_hunt.elk_search("tpot-*", {"size": 0}) == {"hits": {"hits": []}}
    req = responses.calls[0].request
    assert req.headers["Authorization"] == "ApiKey k"


def test_elk_search_requires_elastic_url(monkeypatch):
    monkeypatch.delenv("ELASTIC_URL", raising=False)
    from lab.config import ConfigError
    with pytest.raises(ConfigError):
        sf_hunt.elk_search("tpot-*", {})


@responses.activate
def test_elk_index_doc_failure_is_logged_and_returns_false(monkeypatch, caplog):
    monkeypatch.setenv("ELASTIC_URL", "https://es.example.invalid:9200")
    responses.post("https://es.example.invalid:9200/sf-hunt-logs/_doc", status=400, json={"error": "x"})
    with caplog.at_level(logging.WARNING, logger="sf_hunt"):
        assert sf_hunt.elk_index_doc("sf-hunt-logs", {"a": 1}) is False
    assert any("sf-hunt-logs" in r.getMessage() for r in caplog.records)


def test_renamed_identifiers_and_paths():
    root = Path(sf_hunt.__file__).resolve().parent
    assert sf_hunt.HUNT_LOGS_INDEX == "sf-hunt-logs"
    assert sf_hunt.MEMORY_DIR == root / "state" / "sf"


def test_no_legacy_strings_or_insecure_defaults_in_hunt_module():
    text = Path(sf_hunt.__file__).read_text(encoding="utf-8")
    pat = re.compile(r"1xlozec|tallkitchen|tall kitchen|albundy|10\.0\.0\.1|tk-hunt|verify\s*=\s*False", re.I)
    m = pat.search(text)
    assert not m, m.group(0)
    assert "requests.get(" not in text and "requests.post(" not in text  # all HTTP via lab.http.session
