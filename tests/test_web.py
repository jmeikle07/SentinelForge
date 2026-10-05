import re
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import sf_web

TOKEN = "s3cret-token-0123456789"      # >= 16 characters (sf_web.ADMIN_TOKEN_MIN_LENGTH)
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
    # an encoded slash reaches the handler, which must refuse it (deleting the check must fail this)
    r = client.get("/api/pending-detail/..%2F..%2Fsecrets")
    assert r.status_code == 400 and "UUID" in r.json()["detail"]
    assert client.get("/api/pending-detail/not-a-uuid").status_code == 400
    assert client.get("/api/pending-detail/a%00b").status_code == 400


def test_pending_detail_dot_dot_path_never_reaches_the_filesystem(client, monkeypatch):
    """A literal ../ is normalised away by the HTTP client/router: there is no matching route."""
    monkeypatch.setattr(sf_web, "_require_rule_id",
                        lambda rid: (_ for _ in ()).throw(AssertionError("handler must not run")))
    assert client.get("/api/pending-detail/../../x").status_code == 404


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
    assert r.status_code == 403 and "LAB_ADMIN_TOKEN is not set" in r.json()["detail"]
    r = c.post(f"/api/approve/{GOOD_ID}", headers={"X-Admin-Token": TOKEN})   # even a "matching" guess
    assert r.status_code == 403
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


def _hunt(c, ioc):
    return c.post("/api/hunt", json={"ioc": ioc})


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = FakeClock()
    monkeypatch.setattr(sf_web, "_clock", c)
    return c


def test_web_hunt_rate_limited(client, monkeypatch):
    monkeypatch.setattr(sf_web, "HUNT_RATE_LIMIT", 3)
    monkeypatch.setattr(sf_web, "_run_hunt", lambda ioc: {"ioc": ioc})
    codes = [_hunt(client, "8.8.8.8").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert "Retry-After" in _hunt(client, "x").headers


def test_web_hunt_rate_limit_is_per_client(client, monkeypatch):
    monkeypatch.setattr(sf_web, "HUNT_RATE_LIMIT", 1)
    monkeypatch.setattr(sf_web, "_run_hunt", lambda ioc: {"ioc": ioc})
    assert _hunt(client, "a").status_code == 200
    assert _hunt(client, "a").status_code == 429
    other = TestClient(sf_web.app, client=("198.51.100.7", 5000))
    assert _hunt(other, "a").status_code == 200


def test_web_hunt_rate_window_expires(client, monkeypatch, clock):
    monkeypatch.setattr(sf_web, "HUNT_RATE_LIMIT", 1)
    monkeypatch.setattr(sf_web, "HUNT_RATE_WINDOW", 60.0)
    monkeypatch.setattr(sf_web, "_run_hunt", lambda ioc: {"ioc": ioc})
    assert _hunt(client, "a").status_code == 200
    assert _hunt(client, "a").status_code == 429
    clock.t += 59.0
    assert _hunt(client, "a").status_code == 429          # still inside the window: exact, no sleeping
    clock.t += 1.1
    assert _hunt(client, "a").status_code == 200


def test_run_hunt_logs_failure_of_ip_enrichment_and_still_returns(monkeypatch, caplog):
    class Conn:
        def close(self):
            pass

    monkeypatch.setattr(sf_web.tk, "memory_init_ephemeral", lambda: Conn())
    monkeypatch.setattr(sf_web.tk, "bucket_external_ip",
                        lambda c, ip: (_ for _ in ()).throw(RuntimeError("siem down")))
    with caplog.at_level("WARNING"):
        out = sf_web._run_hunt("8.8.8.8")
    assert out["supported"] is True and out["external"] == {}
    assert out["verdict"]["insufficient_data"] is True            # a failed enrichment is never "benign"
    warnings = [r for r in caplog.records if r.name == "sf_web" and r.levelname == "WARNING"]
    assert len(warnings) == 1 and "siem down" in warnings[0].getMessage()


def _stub_enrichment(monkeypatch, external):
    class Conn:
        def close(self):
            pass

    monkeypatch.setattr(sf_web.tk, "memory_init_ephemeral", lambda: Conn())
    monkeypatch.setattr(sf_web.tk, "bucket_external_ip", lambda c, ip: external)


_ALL_MALICIOUS = {
    "virustotal": {"available": True, "malicious": 60, "suspicious": 0, "total_engines": 90},
    "abuseipdb": {"available": True, "abuse_score": 100},
    "greynoise": {"available": True, "classification": "malicious"},
    "threatfox": {"available": True, "match_count": 9},
    "otx": {"available": True, "pulse_count": 50},
    "spamhaus_drop": {"available": True, "in_drop": False},
}


def test_web_route_all_sources_malicious_is_malicious(monkeypatch):
    _stub_enrichment(monkeypatch, _ALL_MALICIOUS)
    v = sf_web._run_hunt("1.1.1.1")["verdict"]
    assert v["verdict"] == "malicious" and v["action"] == "BLOCK"


def test_web_route_matches_bucket_verdict_directly(monkeypatch):
    ext = dict(_ALL_MALICIOUS, spamhaus_drop={"available": True, "in_drop": True})
    _stub_enrichment(monkeypatch, ext)
    via_web = sf_web._run_hunt("1.1.1.1")["verdict"]
    assert via_web == sf_web.tk.bucket_verdict({}, ext, "ipv4")
    assert via_web["verdict"] == "malicious"      # DROP not capped at SUSPICIOUS


def test_web_route_all_sources_failing_is_not_benign(monkeypatch):
    down = {k: {"available": False, "reason": "429"} for k in _ALL_MALICIOUS}
    _stub_enrichment(monkeypatch, down)
    v = sf_web._run_hunt("8.8.8.8")["verdict"]     # sentinel input: a famously clean IP
    assert v["verdict"] != "benign" and v["verdict"] == "unknown"
    assert v["insufficient_data"] is True and v["action"] == "INSUFFICIENT DATA"


def test_web_route_string_typed_api_fields_do_not_500(client, monkeypatch):
    ext = dict(_ALL_MALICIOUS, abuseipdb={"available": True, "abuse_score": "100"})
    _stub_enrichment(monkeypatch, ext)
    r = _hunt(client, "1.1.1.1")
    assert r.status_code == 200 and r.json()["verdict"]["verdict"] == "malicious"


def test_index_page_never_says_safe_to_allow_for_insufficient_data():
    html = (Path(sf_web.__file__).parent / "web" / "index.html").read_text(encoding="utf-8")
    assert "insufficient_data" in html
    branch = html.index("insufficient_data")
    assert branch < html.index("safe to allow")      # the insufficient branch is checked first


def test_api_pending_corrupt_state_is_a_503_not_an_empty_queue(client, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(sf_web, "HERE", tmp_path)
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "pending_rules.json").write_text("{corrupt", encoding="utf-8")
    with caplog.at_level("ERROR"):
        r = client.get("/api/pending")
    assert r.status_code == 503
    assert "pending_rules" in r.json()["detail"] and "corrupt" in r.json()["detail"]
    assert "pending" not in r.json()                      # no empty list masquerading as "all clear"
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
    assert not re.search(r"1x" r"lozec|ta" r"llkitchen|ta" r"ll kitchen|al" r"bundy", text, re.I)


def test_every_active_rule_technique_has_plain_language_text():
    """A retag must not leave reviewers with no plain-language meaning (T1035 -> T1569.002 did)."""
    from lab import coverage
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    missing = [t for t in coverage.rule_techniques(root / "detections" / "sigma")
               if t.lower() not in sf_web.TECHNIQUE_PLAIN]
    assert not missing, f"techniques with no TECHNIQUE_PLAIN entry: {missing}"
