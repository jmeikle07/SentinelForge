import sys
import time

import pytest
import requests
import responses

import validate_rule

ES = "https://es.test:9200"
OK = {"score": 8, "approve": True, "issues": [], "reasoning": ""}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", ES)
    monkeypatch.setenv("ELASTIC_API_KEY", "k")
    monkeypatch.delenv("LAB_INSECURE_TLS", raising=False)


@responses.activate
def test_backtest_reports_error_when_es_unreachable():
    responses.add(responses.POST, f"{ES}/logs-*/_count", body=requests.ConnectionError("down"))
    count, err = validate_rule.backtest_query("process.name:x")
    assert count == 0 and err


@responses.activate
def test_backtest_query_has_time_range():
    responses.add(responses.POST, f"{ES}/logs-*/_count", json={"count": 3})
    count, err = validate_rule.backtest_query("process.name:x")
    assert (count, err) == (3, None)
    body = responses.calls[0].request.body
    assert b"now-7d" in body and b"@timestamp" in body


def test_backtest_missing_config_is_error(monkeypatch):
    monkeypatch.delenv("ELASTIC_URL")
    count, err = validate_rule.backtest_query("x")
    assert count == 0 and "ELASTIC_URL" in err


def test_passes_requires_successful_backtest():
    assert validate_rule.passes(3, 9.0, 5, None) is True
    assert validate_rule.passes(3, 9.0, 0, None) is False
    assert validate_rule.passes(3, 9.0, 0, "Backtest connection error") is False
    assert validate_rule.passes(1, 9.0, 5, None) is False
    assert validate_rule.passes(3, 5.0, 5, None) is False


def test_validate_fails_when_es_unreachable(tmp_path, monkeypatch):
    rule = tmp_path / "r.yml"
    rule.write_text("title: t\nid: 1\nlogsource: {category: x}\ndetection: {condition: s}\n")
    monkeypatch.setattr(sys, "argv", ["validate_rule.py", str(rule)])
    monkeypatch.setattr(validate_rule, "convert_sigma", lambda p: "q")
    monkeypatch.setattr(validate_rule, "backtest_query", lambda q: (0, "ES down"))
    monkeypatch.setattr(validate_rule, "validate_rule_text", lambda t, q: (3, 9.0, {}))
    monkeypatch.setattr(validate_rule, "heal_rule", lambda *a, **k: "x" * 200)
    monkeypatch.setattr(validate_rule, "send_circuit_breaker_email", lambda *a, **k: None)
    monkeypatch.setattr(validate_rule, "save_validation", lambda *a, **k: None)
    monkeypatch.setattr(validate_rule.time, "sleep", lambda s: None)
    with pytest.raises(SystemExit) as ei:
        validate_rule.main()
    assert ei.value.code == 1


def test_validate_prompt_with_braces_in_rule_does_not_raise():
    rule = "title: {x} {{y}} {0} ${z} %s"
    q = 'a:{"b"} $query'
    prompt = validate_rule.build_validation_prompt(rule, q)
    assert rule in prompt and q in prompt
    heal = validate_rule.build_heal_prompt(rule, q, "info {b}", "fb {c}", 2)
    assert rule in heal and "info {b}" in heal and "fb {c}" in heal


def test_validate_runs_three_voters_concurrently(monkeypatch):
    def slow(result):
        def f(rule_text, query):
            time.sleep(0.4)
            return result
        return f
    monkeypatch.setattr(validate_rule, "ask_ollama", slow(OK))
    monkeypatch.setattr(validate_rule, "ask_claude", slow(OK))
    monkeypatch.setattr(validate_rule, "ask_gemini", slow(OK))
    t0 = time.monotonic()
    approvals, avg, fb = validate_rule.validate_rule_text("r", "q")
    elapsed = time.monotonic() - t0
    assert elapsed < 0.9, f"voters ran serially ({elapsed:.2f}s)"
    assert approvals == 3 and avg == 8 and set(fb) == {"Ollama", "Claude", "Gemini"}


def test_validate_missing_api_key_skips_that_voter_with_warning(monkeypatch, caplog):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(validate_rule, "ask_ollama", lambda r, q: OK)
    monkeypatch.setattr(validate_rule, "ask_gemini", lambda r, q: OK)
    with caplog.at_level("WARNING"):
        approvals, avg, fb = validate_rule.validate_rule_text("r", "q")
    assert "Claude" not in fb and set(fb) == {"Ollama", "Gemini"}
    assert approvals == 2 and avg == 8
    assert any("ANTHROPIC_API_KEY" in r.getMessage() for r in caplog.records)


def test_voter_exception_is_logged_and_counts_as_rejection(monkeypatch, caplog):
    def boom(r, q):
        raise requests.ConnectionError("nope")
    monkeypatch.setattr(validate_rule, "ask_ollama", boom)
    monkeypatch.setattr(validate_rule, "ask_claude", lambda r, q: OK)
    monkeypatch.setattr(validate_rule, "ask_gemini", lambda r, q: OK)
    with caplog.at_level("ERROR"):
        approvals, avg, fb = validate_rule.validate_rule_text("r", "q")
    assert approvals == 2 and fb["Ollama"]["approve"] is False
    assert caplog.records


def test_ecs_pipeline_is_shared_not_duplicated():
    assert not hasattr(validate_rule, "_ecs_fieldmap_pipeline")
