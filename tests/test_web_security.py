"""Web hardening: corrupt state, host allowlist, auth throttling, token strength, limiter hygiene,
safe pending-detail output, no leaked server details."""
import json
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import sf_web

TOKEN = "correct-horse-battery-staple"        # 27 chars
GOOD_ID = str(uuid.uuid4())


class FakeClock:
    def __init__(self):
        self.t = 5000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = FakeClock()
    monkeypatch.setattr(sf_web, "_clock", c)
    return c


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("LAB_ADMIN_TOKEN", TOKEN)
    monkeypatch.delenv("SF_ALLOWED_HOSTS", raising=False)
    sf_web._reset_rate_limits()
    return TestClient(sf_web.app)


@pytest.fixture
def fake_run(monkeypatch):
    calls = []

    class R:
        returncode = 0
        stdout = "done"
        stderr = ""

    monkeypatch.setattr(sf_web.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or R())
    return calls


@pytest.fixture
def home(tmp_path, monkeypatch):
    (tmp_path / "state").mkdir()
    (tmp_path / "detections" / "sigma").mkdir(parents=True)
    (tmp_path / "detections" / "pending").mkdir(parents=True)
    monkeypatch.setattr(sf_web, "HERE", tmp_path)
    return tmp_path


def _write(home, name, payload):
    (home / "state" / name).write_text(
        payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")


# ── W7: corrupt state is an explicit 503, never an empty list ────────────────
def test_corrupt_pending_state_is_503_every_time_not_just_the_first(client, home):
    _write(home, "pending_rules.json", "{corrupt")
    first = client.get("/api/pending")
    assert first.status_code == 503
    # lab.state quarantines the file on first read, so the second request sees NO file. It must not
    # turn into "All clear"; the quarantined file is the evidence that rules may have been lost.
    second = client.get("/api/pending")
    assert second.status_code == 503
    assert "corrupt" in second.json()["detail"] and "pending_rules" in second.json()["detail"]
    assert str(home) not in first.text and str(home) not in second.text      # no server paths


def test_pending_recovers_once_the_quarantine_is_cleared(client, home):
    _write(home, "pending_rules.json", "{corrupt")
    assert client.get("/api/pending").status_code == 503
    (home / "state" / "pending_rules.corrupt").unlink()
    assert client.get("/api/pending").json() == {"pending": []}


def test_wrongly_shaped_state_is_503_not_a_crash(client, home):
    _write(home, "pending_rules.json", {"not": "a list"})
    r = client.get("/api/pending")
    assert r.status_code == 503 and "unexpected" in r.json()["detail"]


def test_engine_dashboard_with_corrupt_log_is_503(client, home):
    _write(home, "hunt_log.json", "][")
    r = client.get("/api/engine")
    assert r.status_code == 503 and "hunt_log" in r.json()["detail"]


def test_missing_state_is_still_a_normal_empty_answer(client, home):
    assert client.get("/api/pending").json() == {"pending": []}
    assert client.get("/api/engine").status_code == 200


# ── W8: empty lists in rules never 500 ───────────────────────────────────────
@pytest.mark.parametrize("field", ["process.name", "process.command_line", "source.ip", "event.code"])
def test_pending_detail_with_empty_list_field_does_not_500(client, home, field):
    (home / "detections" / "pending" / f"{GOOD_ID}.yml").write_text(
        f"title: T\ndescription: d\nlevel: low\ntags: [attack.t1059.001]\n"
        f"detection:\n  selection:\n    {field}: []\n  condition: selection\n", encoding="utf-8")
    r = client.get(f"/api/pending-detail/{GOOD_ID}")
    assert r.status_code == 200 and r.json()["title"] == "T"
    assert "yaml" in r.json()


def test_join_or_handles_every_length():
    assert sf_web._join_or([]) == "nothing"
    assert sf_web._join_or(["a"]) == "a"
    assert sf_web._join_or(["a", "b"]) == "a or b"
    assert sf_web._join_or(list("abcdef")) == "a, b, c or 3 more"
    assert sf_web._join_or("x") == "x"
    assert sf_web._join_or(None) == "None"


def test_oddly_shaped_rule_still_returns_the_raw_yaml(client, home):
    (home / "detections" / "pending" / f"{GOOD_ID}.yml").write_text("- just\n- a list\n", encoding="utf-8")
    r = client.get(f"/api/pending-detail/{GOOD_ID}")
    assert r.status_code == 200 and "just" in r.json()["yaml"] and r.json()["triggers"] == []


# ── W9: POST-only hunt, host allowlist, no leaked server details ─────────────
def test_hunt_is_post_only_and_get_is_405(client):
    assert client.get("/api/hunt", params={"ioc": "8.8.8.8"}).status_code == 405


def test_hunt_post_requires_a_json_body(client, monkeypatch):
    monkeypatch.setattr(sf_web, "_run_hunt", lambda ioc: {"ioc": ioc})
    assert client.post("/api/hunt", json={"ioc": "8.8.8.8"}).status_code == 200
    assert client.post("/api/hunt").status_code == 422
    assert client.post("/api/hunt", json={}).status_code == 422
    assert client.post("/api/hunt", json={"ioc": 5}).status_code == 422
    # a cross-site <form> can only send urlencoded/text: it must not be accepted as an IOC
    assert client.post("/api/hunt", data="ioc=8.8.8.8",
                       headers={"Content-Type": "application/x-www-form-urlencoded"}).status_code == 422
    assert client.post("/api/hunt", content='{"ioc":"8.8.8.8"}',
                       headers={"Content-Type": "text/plain"}).status_code == 422


def test_hunt_ioc_length_is_capped(client, monkeypatch):
    monkeypatch.setattr(sf_web, "_run_hunt", lambda ioc: {"ioc": ioc})
    assert client.post("/api/hunt", json={"ioc": "a" * 1000}).status_code == 422


def test_unknown_host_header_is_rejected(client):
    assert client.get("/api/pending", headers={"Host": "evil.example"}).status_code == 400
    assert client.get("/api/pending", headers={"Host": "rebind.evil.example:8000"}).status_code == 400
    for ok in ("localhost", "localhost:8000", "127.0.0.1:8000", "testserver"):
        assert client.get("/api/pending", headers={"Host": ok}).status_code == 200, ok


def test_allowed_hosts_are_configurable_by_env(client, monkeypatch):
    monkeypatch.setenv("SF_ALLOWED_HOSTS", "lab.example.org, *.corp.example.org")
    assert client.get("/api/pending", headers={"Host": "lab.example.org"}).status_code == 200
    assert client.get("/api/pending", headers={"Host": "a.corp.example.org:8443"}).status_code == 200
    assert client.get("/api/pending", headers={"Host": "localhost"}).status_code == 400   # replaced, not extended


def test_pages_are_also_behind_the_host_check(client):
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400
    assert client.get("/engine", headers={"Host": "evil.example"}).status_code == 400


def test_engine_timeline_exposes_no_server_paths_or_exception_text(client, home):
    _write(home, "hunt_log.json", [
        {"timestamp": "2026-05-15T18:02:48+00:00", "result": "hunt_triggered_generation_failed",
         "ioc": "77.83.240.70", "triggered_by_hunt_id": "abc", "error": "KeyError: 'detection_focus'"},
        {"timestamp": "2026-05-14T00:00:00+00:00", "result": "deployed", "technique_id": "T1059.001",
         "technique_name": "PowerShell", "confidence": "high", "rule_id": GOOD_ID,
         "filepath": "/home/lab/detections/sigma/x.yml", "lookback": 60},
    ])
    body = client.get("/api/engine").json()
    blob = json.dumps(body["timeline"])
    assert "/home/lab" not in blob and "KeyError" not in blob and "detection_focus" not in blob
    assert "filepath" not in blob and "77.83.240.70" not in blob
    assert [e["result"] for e in body["timeline"]] == ["hunt_triggered_generation_failed", "deployed"]
    deployed = body["timeline"][1]
    assert deployed["technique_id"] == "T1059.001" and deployed["rule_id"] == GOOD_ID
    assert body["outcomes"]["deployed"] == 1                       # counts still use the full log


def test_pending_detail_never_leaks_paths_or_exceptions(client, home):
    (home / "detections" / "pending" / f"{GOOD_ID}.yml").write_text(
        "title: [unclosed\n  nope: : :\n", encoding="utf-8")
    r = client.get(f"/api/pending-detail/{GOOD_ID}")
    assert r.status_code == 200
    assert str(home) not in r.text and "Traceback" not in r.text and "YAMLError" not in r.text
    assert r.json()["title"] is None and "unclosed" in r.json()["yaml"]


# ── W10: failed-auth throttling and token strength ───────────────────────────
def _approve(c, token):
    return c.post(f"/api/approve/{GOOD_ID}", headers={"X-Admin-Token": token})


def test_repeated_wrong_tokens_lock_the_client_out_even_for_the_right_token(client, fake_run, clock, monkeypatch):
    monkeypatch.setattr(sf_web, "AUTH_FAIL_LIMIT", 3)
    monkeypatch.setattr(sf_web, "AUTH_FAIL_WINDOW", 300.0)
    assert [_approve(client, "x" * 20).status_code for _ in range(3)] == [401, 401, 401]
    locked = _approve(client, TOKEN)
    assert locked.status_code == 429 and int(locked.headers["Retry-After"]) >= 1
    assert fake_run == []
    clock.t += 301
    assert _approve(client, TOKEN).status_code == 200
    assert len(fake_run) == 1


def test_lockout_is_per_client_and_covers_reject_too(client, fake_run, clock, monkeypatch):
    monkeypatch.setattr(sf_web, "AUTH_FAIL_LIMIT", 2)
    for _ in range(2):
        assert client.post(f"/api/reject/{GOOD_ID}", headers={"X-Admin-Token": "nope" * 5}).status_code == 401
    assert client.post(f"/api/reject/{GOOD_ID}", headers={"X-Admin-Token": TOKEN}).status_code == 429
    other = TestClient(sf_web.app, client=("198.51.100.9", 4000))
    assert _approve(other, TOKEN).status_code == 200


def test_missing_token_header_counts_as_a_failure(client, fake_run, clock, monkeypatch):
    monkeypatch.setattr(sf_web, "AUTH_FAIL_LIMIT", 2)
    assert client.post(f"/api/approve/{GOOD_ID}").status_code == 401
    assert client.post(f"/api/approve/{GOOD_ID}").status_code == 401
    assert _approve(client, TOKEN).status_code == 429


def test_success_resets_the_failure_count(client, fake_run, clock, monkeypatch):
    monkeypatch.setattr(sf_web, "AUTH_FAIL_LIMIT", 3)
    for _ in range(2):
        _approve(client, "wrong" * 5)
    assert _approve(client, TOKEN).status_code == 200
    for _ in range(2):
        assert _approve(client, "wrong" * 5).status_code == 401      # would be 429 if counts had carried over


@pytest.mark.parametrize("token", ["short", "x" * 15, "change-me"])
def test_token_shorter_than_16_disables_the_routes_with_a_clear_message(monkeypatch, fake_run, token):
    monkeypatch.setenv("LAB_ADMIN_TOKEN", token)
    sf_web._reset_rate_limits()
    r = _approve(TestClient(sf_web.app), token)          # even the "matching" value is refused
    assert r.status_code == 403
    assert "16" in r.json()["detail"] and "LAB_ADMIN_TOKEN" in r.json()["detail"]
    assert fake_run == []


def test_token_of_exactly_16_characters_is_accepted(monkeypatch, fake_run):
    monkeypatch.setenv("LAB_ADMIN_TOKEN", "a" * 16)
    sf_web._reset_rate_limits()
    assert _approve(TestClient(sf_web.app), "a" * 16).status_code == 200


def test_setup_doc_does_not_teach_a_weak_token():
    text = (Path(sf_web.__file__).parent / "docs" / "SETUP.md").read_text(encoding="utf-8")
    assert "change-me" not in text
    assert "16" in text and "SF_ALLOWED_HOSTS" in text and "--proxy-headers" in text


# ── W11: limiter hygiene ─────────────────────────────────────────────────────
def test_idle_clients_are_evicted_from_the_rate_limit_table(client, monkeypatch, clock):
    monkeypatch.setattr(sf_web, "_run_hunt", lambda ioc: {"ioc": ioc})
    monkeypatch.setattr(sf_web, "HUNT_RATE_WINDOW", 60.0)
    for i in range(50):
        c = TestClient(sf_web.app, client=(f"203.0.113.{i}", 1000 + i))
        assert c.post("/api/hunt", json={"ioc": "8.8.8.8"}).status_code == 200
    assert len(sf_web._rate_hits) == 50
    clock.t += 61
    TestClient(sf_web.app, client=("198.51.100.1", 1)).post("/api/hunt", json={"ioc": "8.8.8.8"})
    assert len(sf_web._rate_hits) == 1                   # only the live client remains


def test_failed_auth_table_is_pruned_too(client, clock, monkeypatch, fake_run):
    for i in range(20):
        c = TestClient(sf_web.app, client=(f"203.0.113.{i}", 1000 + i))
        _approve(c, "bad" * 8)
    assert len(sf_web._auth_fails) == 20
    clock.t += sf_web.AUTH_FAIL_WINDOW + 1
    _approve(TestClient(sf_web.app, client=("198.51.100.1", 1)), "bad" * 8)
    assert len(sf_web._auth_fails) == 1


# ── W12: technique text falls back gracefully ────────────────────────────────
def test_unknown_technique_gets_generic_text_naming_the_id():
    txt = sf_web._technique_plain(["attack.discovery", "attack.t9999.123"])
    assert txt and "T9999.123" in txt
    assert txt not in sf_web.TECHNIQUE_PLAIN.values()


def test_known_technique_still_gets_its_specific_text():
    assert sf_web._technique_plain(["attack.t1082"]) == sf_web.TECHNIQUE_PLAIN["t1082"]


def test_no_technique_tag_at_all_gets_generic_text_not_none():
    assert sf_web._technique_plain([]) and sf_web._technique_plain(None)
    assert sf_web._technique_plain(["attack.g0016", "attack.execution"])      # group and tactic tags only


def test_pending_detail_for_unknown_technique_has_a_meaning(client, home):
    (home / "detections" / "pending" / f"{GOOD_ID}.yml").write_text(
        "title: T\ndescription: d\nlevel: low\ntags: [attack.t9999]\n"
        "detection:\n  selection:\n    process.name: a.exe\n  condition: selection\n", encoding="utf-8")
    assert "T9999" in client.get(f"/api/pending-detail/{GOOD_ID}").json()["meaning"]
