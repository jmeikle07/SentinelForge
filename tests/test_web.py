import json
import re
import sys
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import sf_web

TOKEN = "s3cret-token"
GOOD_ID = str(uuid.uuid4())


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("LAB_ADMIN_TOKEN", TOKEN)
    sf_web._reset_rate_limits()
    return TestClient(sf_web.app)


@pytest.fixture
def fake_run(monkeypatch):
    calls = []

    class R:
        returncode = 0
        stdout = "done"
        stderr = ""

    def fake(cmd, **kw):
        calls.append((cmd, kw))
        return R()

    monkeypatch.setattr(sf_web.subprocess, "run", fake)
    return calls


@pytest.mark.parametrize("action", ["approve", "reject"])
@pytest.mark.parametrize("bad", ["..%2Fx", "not-a-uuid", "1234", "..%5C..%5Cetc"])
def test_web_approve_rejects_non_uuid_rule_id(client, fake_run, action, bad):
    r = client.post(f"/api/{action}/{bad}", headers={"X-Admin-Token": TOKEN})
    assert r.status_code == 400
    assert fake_run == []  # nothing was executed


def test_pending_detail_rejects_non_uuid_rule_id(client):
    assert client.get("/api/pending-detail/..%2F..%2Fsecrets").status_code in (400, 404)
    assert client.get("/api/pending-detail/not-a-uuid").status_code == 400


@pytest.mark.parametrize("headers", [{}, {"X-Admin-Token": "wrong"}])
def test_web_approve_requires_token_header(client, fake_run, headers):
    r = client.post(f"/api/approve/{GOOD_ID}", headers=headers)
    assert r.status_code == 401
    assert fake_run == []


def test_web_approve_with_token_works_regardless_of_client_host(client, fake_run):
    # TestClient's client host is "testclient": the old localhost-only check would 403 here.
    r = client.post(f"/api/approve/{GOOD_ID}", headers={"X-Admin-Token": TOKEN})
    assert r.status_code == 200 and r.json()["ok"] is True


def test_web_approve_disabled_when_no_token_configured(monkeypatch, fake_run):
    monkeypatch.delenv("LAB_ADMIN_TOKEN", raising=False)
    c = TestClient(sf_web.app)
    r = c.post(f"/api/approve/{GOOD_ID}", headers={"X-Admin-Token": ""})
    assert r.status_code in (401, 403, 503)
    assert fake_run == []


def test_web_uses_sys_executable_not_python3(client, fake_run):
    client.post(f"/api/approve/{GOOD_ID}", headers={"X-Admin-Token": TOKEN})
    client.post(f"/api/reject/{GOOD_ID}", headers={"X-Admin-Token": TOKEN})
    assert len(fake_run) == 2
    for cmd, kw in fake_run:
        assert cmd[0] == sys.executable
        assert "python3" not in cmd
        assert cmd[-1] == GOOD_ID
        assert kw.get("timeout")  # never hang the worker
    assert "python3" not in Path(sf_web.__file__).read_text(encoding="utf-8")


def test_web_hunt_rate_limited(client, monkeypatch):
    monkeypatch.setattr(sf_web, "HUNT_RATE_LIMIT", 3)
    monkeypatch.setattr(sf_web, "_run_hunt", lambda ioc: {"ioc": ioc})
    codes = [client.get("/api/hunt", params={"ioc": "203.0.113.9"}).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert "Retry-After" in client.get("/api/hunt", params={"ioc": "x"}).headers


def test_web_hunt_rate_limit_is_per_client(client, monkeypatch):
    monkeypatch.setattr(sf_web, "HUNT_RATE_LIMIT", 1)
    monkeypatch.setattr(sf_web, "_run_hunt", lambda ioc: {"ioc": ioc})
    assert client.get("/api/hunt", params={"ioc": "a"}).status_code == 200
    assert client.get("/api/hunt", params={"ioc": "a"}).status_code == 429
    other = TestClient(sf_web.app, client=("198.51.100.7", 5000))
    assert other.get("/api/hunt", params={"ioc": "a"}).status_code == 200


def test_web_hunt_rate_window_expires(client, monkeypatch):
    monkeypatch.setattr(sf_web, "HUNT_RATE_LIMIT", 1)
    monkeypatch.setattr(sf_web, "HUNT_RATE_WINDOW", 0.2)
    monkeypatch.setattr(sf_web, "_run_hunt", lambda ioc: {"ioc": ioc})
    assert client.get("/api/hunt", params={"ioc": "a"}).status_code == 200
    assert client.get("/api/hunt", params={"ioc": "a"}).status_code == 429
    time.sleep(0.3)
    assert client.get("/api/hunt", params={"ioc": "a"}).status_code == 200


def test_run_hunt_logs_failure_of_ip_enrichment_and_still_returns(monkeypatch, caplog):
    class Conn:
        def close(self):
            pass

    monkeypatch.setattr(sf_web.tk, "memory_init", lambda: Conn())
    monkeypatch.setattr(sf_web.tk, "bucket_external_ip",
                        lambda c, ip: (_ for _ in ()).throw(RuntimeError("siem down")))
    with caplog.at_level("WARNING"):
        out = sf_web._run_hunt("203.0.113.9")
    assert out["supported"] is True and out["external"] == {}
    assert any("siem down" in r.getMessage() or "203.0.113.9" in r.getMessage() for r in caplog.records)


def test_api_pending_reads_state_and_logs_corrupt_file(client, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(sf_web, "HERE", tmp_path)
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "pending_rules.json").write_text("{corrupt", encoding="utf-8")
    with caplog.at_level("ERROR"):
        r = client.get("/api/pending")
    assert r.status_code == 200 and r.json() == {"pending": []}
    assert any("pending_rules" in rec.getMessage() for rec in caplog.records)
    assert (tmp_path / "state" / "pending_rules.corrupt").exists()


def test_api_pending_detail_valid_uuid_returns_rule(client, tmp_path, monkeypatch):
    monkeypatch.setattr(sf_web, "HERE", tmp_path)
    pend = tmp_path / "detections" / "pending"
    pend.mkdir(parents=True)
    (pend / f"{GOOD_ID}.yml").write_text(
        "title: T\ndescription: d\nlevel: low\ntags: [attack.t1059.001]\n"
        "detection:\n  selection:\n    process.name: powershell.exe\n  condition: selection\n",
        encoding="utf-8")
    body = client.get(f"/api/pending-detail/{GOOD_ID}").json()
    assert body["title"] == "T" and body["triggers"]
    assert client.get(f"/api/pending-detail/{uuid.uuid4()}").status_code == 404


def test_existing_routes_and_branding(client):
    paths = {r.path for r in sf_web.app.routes}
    assert {"/", "/review", "/engine", "/api/hunt", "/api/engine", "/api/pending"} <= paths
    assert sf_web.app.title.startswith("SentinelForge")
    text = Path(sf_web.__file__).read_text(encoding="utf-8")
    assert not re.search(r"1xlozec|tallkitchen|tall kitchen|albundy", text, re.I)
