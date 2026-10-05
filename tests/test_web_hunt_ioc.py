"""W4 (HTTP 400 with a reason, before any third-party call) and W6 (web lookups are not persisted)."""
import logging

import pytest
from fastapi.testclient import TestClient

import sf_hunt
import sf_web


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(sf_hunt, "MEMORY_DIR", tmp_path)
    monkeypatch.setattr(sf_hunt, "MEMORY_DB", tmp_path / "hunt_memory.db")
    monkeypatch.setattr(sf_hunt, "_EPHEMERAL_CONN", None)
    sf_web._reset_rate_limits()

    def boom(*a, **k):
        raise AssertionError("third-party call attempted")

    for fn in ("bucket_external_ip", "bucket_external_domain", "bucket_external_hash"):
        monkeypatch.setattr(sf_hunt, fn, boom)
    return TestClient(sf_web.app)


@pytest.mark.parametrize("ioc,fragment", [
    ("10.0.0.1", "non-public"),
    ("127.0.0.1", "non-public"),
    ("192.168.1.20", "non-public"),
    ("dc01.corp.local", "non-public"),
    ("dc01", "non-public"),
    ("١.٢.٣.٤", "not a valid"),
    ("08.8.8.8", "not a valid"),
    ("http://example.com/x", "not a valid"),
    ("2001:db8::1", "not a valid"),
    ("   ", "empty"),
])
def test_rejected_iocs_get_400_with_a_reason_and_no_third_party_call(client, ioc, fragment):
    r = client.get("/api/hunt", params={"ioc": ioc})
    assert r.status_code == 400
    assert fragment in r.json()["detail"].lower()


def test_valid_ioc_is_canonicalised_before_the_lookup(client, monkeypatch):
    seen = []
    monkeypatch.setattr(sf_hunt, "bucket_external_domain", lambda conn, d: seen.append(d) or {})
    r = client.get("/api/hunt", params={"ioc": "  EXAMPLE.com "})
    assert r.status_code == 200 and seen == ["example.com"] and r.json()["ioc"] == "example.com"


def test_web_lookup_is_never_written_to_disk(client, monkeypatch, tmp_path):
    def fake(conn, ip):
        sf_hunt.cache_put(conn, ip, "otx", {"available": True, "pulse_count": 0})
        return {"otx": {"available": True, "pulse_count": 0}}

    monkeypatch.setattr(sf_hunt, "bucket_external_ip", fake)
    assert client.get("/api/hunt", params={"ioc": "8.8.8.8"}).status_code == 200
    assert not (tmp_path / "hunt_memory.db").exists()
    assert list(tmp_path.iterdir()) == []
    # ...but the in-memory cache did keep it (that is what saves upstream quota)
    assert sf_hunt.cache_get(sf_hunt.memory_init_ephemeral(), "8.8.8.8", "otx") is not None


def test_failure_log_does_not_contain_the_ioc(client, monkeypatch, caplog):
    def fail(conn, ip):
        raise RuntimeError("siem down")

    monkeypatch.setattr(sf_hunt, "bucket_external_ip", fail)
    with caplog.at_level(logging.DEBUG):
        r = client.get("/api/hunt", params={"ioc": "8.8.4.4"})
    assert r.status_code == 200
    ours = " ".join(rec.getMessage() for rec in caplog.records if rec.name.startswith("sf_"))
    assert "siem down" in ours
    assert "8.8.4.4" not in ours


def test_index_page_describes_what_is_stored():
    from pathlib import Path
    html = (Path(sf_web.__file__).parent / "web" / "index.html").read_text(encoding="utf-8")
    assert "nothing you type is saved" not in html.lower()
    low = html.lower()
    assert "third-party" in low or "third party" in low        # says the IOC is sent to external services
    assert "memory" in low and "disk" in low                    # says where it is (not) kept
