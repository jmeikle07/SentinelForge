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


# ── W15: layer 8 gets the REAL existing rules ────────────────────────────────

WHITELIST_RULE = """title: Internal allowlist for known scanner
id: 11111111-2222-3333-4444-555555555555
status: experimental
tags:
  - allowlist
  - attack.t1046
detection:
  selection:
    src_ip: {ip}
  condition: selection
"""


@pytest.fixture
def rules_dir(monkeypatch, tmp_path):
    import hunt_water_rules as hwr
    d = tmp_path / "sigma"
    (d / "hunt-triggered").mkdir(parents=True)
    monkeypatch.setattr(hwr, "SIGMA_DIR", d)
    monkeypatch.setattr(hwr, "SIGMA_HUNT_DIR", d / "hunt-triggered")
    hwr._PARSE_CACHE.clear()
    return d


def test_pass_receives_real_existing_rules_not_empty_list(harness, rules_dir, monkeypatch):
    (rules_dir / "ok.yml").write_text(WHITELIST_RULE.format(ip="203.0.113.77"), encoding="utf-8")
    seen = {}
    real = wht.water_should_generate_rule_from_verdict

    def spy(record, existing_rules=None, rate_limiter=None):
        seen["rules"] = existing_rules
        return real(record, existing_rules=existing_rules, rate_limiter=rate_limiter)

    monkeypatch.setattr(wht, "water_should_generate_rule_from_verdict", spy)
    harness.run([_good()])
    assert [r["title"] for r in seen["rules"]] == ["Internal allowlist for known scanner"]


def test_allowlist_rule_naming_the_ioc_blocks_generation(harness, rules_dir):
    (rules_dir / "wl.yml").write_text(WHITELIST_RULE.format(ip="8.8.4.4"), encoding="utf-8")
    n, _ = harness.run([_good()])
    assert n == 0 and harness.calls == [] and harness.lim.used == 0


def test_allowlist_cidr_covering_the_ioc_blocks_generation(harness, rules_dir):
    (rules_dir / "wl.yml").write_text(WHITELIST_RULE.format(ip="'8.8.4.0/24'"), encoding="utf-8")
    n, _ = harness.run([_good()])
    assert n == 0 and harness.calls == []


def test_allowlist_for_a_different_ip_does_not_block(harness, rules_dir):
    (rules_dir / "wl.yml").write_text(WHITELIST_RULE.format(ip="18.8.4.40"), encoding="utf-8")
    n, _ = harness.run([_good()])
    assert n == 1


def test_deprecated_allowlist_is_not_active_and_does_not_block(harness, rules_dir):
    (rules_dir / "wl.yml").write_text(
        WHITELIST_RULE.format(ip="8.8.4.4").replace("experimental", "deprecated"), encoding="utf-8")
    n, _ = harness.run([_good()])
    assert n == 1


def test_unreadable_rule_file_fails_closed_and_is_logged(harness, rules_dir, caplog):
    (rules_dir / "broken.yml").write_text("title: [unclosed\n  x: : :\n", encoding="utf-8")
    with caplog.at_level(logging.ERROR, logger="water_hunt_trigger"):
        n, _ = harness.run([_good()])
    assert n == 0 and harness.calls == [] and harness.lim.used == 0
    assert any("broken.yml" in r.getMessage() for r in caplog.records)


def test_missing_rules_dir_means_no_rules_not_a_crash(harness, monkeypatch, tmp_path):
    import hunt_water_rules as hwr
    monkeypatch.setattr(hwr, "SIGMA_DIR", tmp_path / "nope")
    monkeypatch.setattr(hwr, "SIGMA_HUNT_DIR", tmp_path / "nope" / "h")
    hwr._PARSE_CACHE.clear()
    n, _ = harness.run([_good()])
    assert n == 1


# ── W17: technique inference, tactics, detection focus ───────────────────────

def test_passive_sensors_do_not_vote_for_a_technique():
    observed = {"honeypots": [{"name": "P0f", "count": 395966}, {"name": "Suricata", "count": 137470},
                              {"name": "Fatt", "count": 99999}, {"name": "Cowrie", "count": 383}]}
    inferred = wht.infer_technique_from_observed(observed)
    assert inferred["technique_id"] == "T1110.001"
    assert inferred["honeypots_seen"] == ["Cowrie"]


def test_only_passive_sensors_means_no_technique():
    observed = {"honeypots": [{"name": "P0f", "count": 10}, {"name": "Suricata", "count": 10}]}
    assert wht.infer_technique_from_observed(observed) is None


def test_passive_sensors_are_not_in_the_mapping_at_all():
    for name in wht.PASSIVE_SENSORS:
        assert name not in wht.HONEYPOT_TO_TECHNIQUE


def test_honeypot_names_match_case_insensitively():
    inferred = wht.infer_technique_from_observed({"honeypots": [{"name": "cowrie", "count": 3}]})
    assert inferred and inferred["technique_id"] == "T1110.001"


def test_all_mapped_tactics_are_valid_attack_tactics():
    from lab import coverage
    for name, m in wht.HONEYPOT_TO_TECHNIQUE.items():
        assert m["tactic"] in coverage.TACTICS, name
        for t in m.get("tactics", []):
            assert t in coverage.TACTICS, (name, t)


def test_valid_accounts_is_not_credential_access():
    m = wht.HONEYPOT_TO_TECHNIQUE["Redishoneypot"]
    assert m["id"] == "T1078" and m["tactic"] != "credential-access"
    assert set(m["tactics"]) == {"initial-access", "persistence", "privilege-escalation", "defense-evasion"}
    assert m["tactic"] in m["tactics"]


def test_inference_reports_all_tactics():
    inferred = wht.infer_technique_from_observed({"honeypots": [{"name": "Redishoneypot", "count": 4}]})
    assert "persistence" in inferred["tactics"] and inferred["tactic"] == "initial-access"


def test_detection_focus_follows_technique(harness):
    def focus(honeypot):
        rec = _good()
        rec["result"]["observed"]["honeypots"] = [{"name": honeypot, "count": 9}]
        harness.calls.clear()
        harness.run([rec])
        return harness.calls[0][1]["detection_focus"].lower()

    ssh = focus("Cowrie")
    assert "brute" in ssh or "password" in ssh
    assert "port" not in ssh.replace("distinct", "")
    assert "exploit" in focus("Tanner")
    scan = focus("Honeytrap")
    assert "port" in scan and "scan" in scan


def test_detection_focus_has_generic_fallback_for_unlisted_technique():
    text = wht.detection_focus_for("T9999", "Something New", "8.8.4.4")
    assert "8.8.4.4" in text and "Something New" in text and "T9999" in text
