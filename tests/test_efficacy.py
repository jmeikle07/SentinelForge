import json

import pytest
import responses

import rule_efficacy
from lab import es, http

BASE = "https://es.example.test:9200"
ALERTS = ".alerts-security.alerts-default"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", BASE)
    monkeypatch.setenv("ELASTIC_API_KEY", "k")


def _techs(n):
    return {f"T1{i:03d}": {"technique_name": f"n{i}", "tactic": "t"} for i in range(n)}


@responses.activate
def test_efficacy_makes_one_request_for_36_rules():
    seen = _techs(36)
    buckets = [{"key": "attack.t1000", "doc_count": 4,
                "first": {"value_as_string": "2026-01-01T00:00:00Z"},
                "last": {"value_as_string": "2026-01-02T00:00:00Z"}}]
    responses.add(responses.POST, f"{BASE}/{ALERTS}/_search",
                  json={"aggregations": {"by_tag": {"buckets": buckets}}})
    out = rule_efficacy.fires_for_techniques(http.session(), list(seen))
    assert len(responses.calls) == 1
    body = json.loads(responses.calls[0].request.body)
    assert body["size"] == 0
    agg = body["aggs"]["by_tag"]
    assert agg["terms"]["field"] == "kibana.alert.rule.tags"
    assert set(agg["aggs"]) == {"first", "last"}
    assert out["T1000"] == (4, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    assert out["T1001"] == (0, None, None)
    assert len(out) == 36


def test_efficacy_targets_alerts_alias():
    assert rule_efficacy.ALERTS_INDEX == ".alerts-security.alerts-default"
    assert ".internal" not in rule_efficacy.ALERTS_INDEX


@responses.activate
def test_efficacy_raises_when_es_errors():
    responses.add(responses.POST, f"{BASE}/{ALERTS}/_search", status=500)
    with pytest.raises(es.SearchError):
        rule_efficacy.fires_for_techniques(http.session(retries=0), ["T1059.001"])


@responses.activate
def test_main_writes_results_and_survives_es_failure(tmp_path, monkeypatch):
    (tmp_path / "seen_techniques.json").write_text(json.dumps(_techs(2)))
    monkeypatch.setattr(rule_efficacy, "STATE_DIR", tmp_path)
    real = http.session
    monkeypatch.setattr(rule_efficacy.http, "session", lambda *a, **k: real(retries=0))
    responses.add(responses.POST, f"{BASE}/{ALERTS}/_search", status=503)
    rc = rule_efficacy.main()
    assert rc == 1
    data = json.loads((tmp_path / "rule_efficacy.json").read_text())
    assert data["rules_error"] == 2


def test_backtest_query_has_time_range():
    body = es.backtest_body("process.name:foo", days=7)
    flt = body["query"]["bool"]["filter"]
    assert {"range": {"@timestamp": {"gte": "now-7d"}}} in flt
    assert any("query_string" in f and f["query_string"]["query"] == "process.name:foo" for f in flt)


@responses.activate
def test_backtest_count_posts_to_count_endpoint():
    responses.add(responses.POST, f"{BASE}/logs-*/_count", json={"count": 3})
    assert es.backtest_count(http.session(), "x:y", base_url=BASE, api_key="k") == 3
    assert "now-7d" in responses.calls[0].request.body.decode()


@responses.activate
def test_backtest_count_raises_on_failure():
    responses.add(responses.POST, f"{BASE}/logs-*/_count", status=500)
    with pytest.raises(es.SearchError):
        es.backtest_count(http.session(retries=0), "x:y", base_url=BASE)


def test_help_does_not_run_the_tool_or_touch_state(tmp_path, monkeypatch, capsys):
    """`rule_efficacy.py --help` used to execute the whole run and overwrite state/rule_efficacy.json."""
    (tmp_path / "seen_techniques.json").write_text(json.dumps(_techs(2)))
    monkeypatch.setattr(rule_efficacy, "STATE_DIR", tmp_path)
    with pytest.raises(SystemExit) as exc:
        rule_efficacy.main(["--help"])
    assert exc.value.code == 0
    assert not (tmp_path / "rule_efficacy.json").exists()
    assert "usage" in capsys.readouterr().out.lower()


def test_unknown_argument_is_rejected_without_running(tmp_path, monkeypatch):
    (tmp_path / "seen_techniques.json").write_text(json.dumps(_techs(2)))
    monkeypatch.setattr(rule_efficacy, "STATE_DIR", tmp_path)
    with pytest.raises(SystemExit) as exc:
        rule_efficacy.main(["--bogus"])
    assert exc.value.code == 2
    assert not (tmp_path / "rule_efficacy.json").exists()
