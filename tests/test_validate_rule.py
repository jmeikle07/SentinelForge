import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
import responses

import validate_rule
from lab import ecs
from lab import es as lab_es
from lab.kibana_rule import INDICES

ES = "https://es.test:9200"
COUNT_URL = f"{ES}/{','.join(INDICES)}/_count"
OK = {"score": 8, "approve": True, "issues": [], "reasoning": "", "valid": True}
RULE_ID = "11111111-2222-3333-4444-555555555555"
RULE = f"""title: Test Rule
id: {RULE_ID}
status: test
description: Detects PowerShell execution with an encoded command argument, used for testing.
author: x
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process.name: powershell.exe
    condition: selection
level: medium
"""


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", ES)
    monkeypatch.setenv("ELASTIC_API_KEY", "k")
    monkeypatch.delenv("LAB_INSECURE_TLS", raising=False)


# -- backtest: one implementation (lab.es), same indices as the deploy payload ----------

@responses.activate
def test_backtest_reports_error_when_es_unreachable():
    responses.add(responses.POST, COUNT_URL, body=requests.ConnectionError("down"))
    count, err = validate_rule.backtest_query("process.name:x")
    assert count == 0 and err


@responses.activate
def test_backtest_query_has_time_range_and_uses_deploy_indices():
    responses.add(responses.POST, COUNT_URL, json={"count": 3})
    count, err = validate_rule.backtest_query("process.name:x")
    assert (count, err) == (3, None)
    req = responses.calls[0].request
    assert b"now-7d" in req.body and b"@timestamp" in req.body
    for idx in INDICES:
        assert idx in req.url
    assert req.headers["Authorization"] == "ApiKey k"


def test_backtest_delegates_to_lab_es(monkeypatch):
    seen = {}

    def fake(session, lucene, days=7, index="logs-*", *, base_url=None, api_key=None):
        seen.update(lucene=lucene, days=days, index=index, base_url=base_url, api_key=api_key)
        return 42
    monkeypatch.setattr(lab_es, "backtest_count", fake)
    assert validate_rule.backtest_query("a:b") == (42, None)
    assert seen == {"lucene": "a:b", "days": 7, "index": ",".join(INDICES),
                    "base_url": ES, "api_key": "k"}


def test_backtest_search_error_becomes_error_message(monkeypatch):
    def boom(*a, **k):
        raise lab_es.SearchError("count failed")
    monkeypatch.setattr(lab_es, "backtest_count", boom)
    count, err = validate_rule.backtest_query("x")
    assert count == 0 and "count failed" in err


def test_backtest_missing_config_is_error(monkeypatch):
    monkeypatch.delenv("ELASTIC_URL")
    count, err = validate_rule.backtest_query("x")
    assert count == 0 and "ELASTIC_URL" in err


def test_no_second_backtest_implementation_left():
    assert not hasattr(validate_rule, "BACKTEST_WINDOW")


# -- pass/fail -------------------------------------------------------------------

def test_passes_requires_successful_backtest():
    assert validate_rule.passes(3, 9.0, 5, None) is True
    assert validate_rule.passes(3, 9.0, 0, None) is False
    assert validate_rule.passes(3, 9.0, 0, "Backtest connection error") is False
    assert validate_rule.passes(1, 9.0, 5, None) is False
    assert validate_rule.passes(3, 5.0, 5, None) is False


def test_passes_requires_quorum_of_valid_voters():
    assert validate_rule.MIN_VALID_VOTERS == 2
    assert validate_rule.passes(2, 9.0, 5, None, valid_voters=2) is True
    assert validate_rule.passes(2, 9.0, 5, None, valid_voters=1) is False
    assert validate_rule.passes(3, 9.0, 5, None, valid_voters=0) is False


def test_passes_rejects_obviously_noisy_rule():
    cap = validate_rule.MAX_BACKTEST_HITS
    assert cap > 0
    assert validate_rule.passes(3, 9.0, cap, None) is True
    assert validate_rule.passes(3, 9.0, cap + 1, None) is False


def test_failure_reasons_explain_every_cause():
    r = validate_rule.failure_reasons(1, 4.0, validate_rule.MAX_BACKTEST_HITS + 1, None, valid_voters=1)
    text = " | ".join(r)
    assert "approved" in text and "avg score" in text and "quorum" in text and "too many" in text
    assert any("0 backtest hits" in x for x in validate_rule.failure_reasons(3, 9.0, 0, None, 3))
    assert any("backtest failed: ES down" in x for x in validate_rule.failure_reasons(3, 9.0, 0, "ES down", 3))
    assert validate_rule.failure_reasons(3, 9.0, 5, None, 3) == []


def test_count_valid_counts_only_well_formed_votes():
    fb = {"A": OK, "B": {**OK, "valid": False}, "C": {"score": 1, "approve": False}}
    assert validate_rule.count_valid(fb) == 1


# -- vote normalisation (fail closed) -----------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    (True, True), (False, False), ("true", True), ("TRUE", True), (" True ", True),
    ("false", False), ("False", False),
])
def test_normalize_vote_accepts_only_real_booleans_or_true_false_strings(raw, expected):
    v = validate_rule.normalize_vote({"score": 8, "approve": raw})
    assert v["valid"] is True and v["approve"] is expected


@pytest.mark.parametrize("raw", ["yes", "no", "approve", "", 1, 0, None, [], {}, "truee"])
def test_normalize_vote_rejects_other_approve_values(raw):
    v = validate_rule.normalize_vote({"score": 9, "approve": raw})
    assert v["valid"] is False and v["approve"] is False and v["score"] == 0
    assert "invalid response" in " ".join(v["issues"])


def test_missing_approve_is_invalid_not_approval():
    v = validate_rule.normalize_vote({"score": 9})
    assert v["valid"] is False and v["approve"] is False


@pytest.mark.parametrize("raw", ["high", "", None, [], {}, True, float("nan"), float("inf")])
def test_normalize_vote_non_numeric_score_is_invalid_response(raw):
    v = validate_rule.normalize_vote({"score": raw, "approve": True})
    assert v["valid"] is False and v["approve"] is False and v["score"] == 0
    assert "invalid response" in " ".join(v["issues"])


@pytest.mark.parametrize("raw,expected", [(1000, 10), (-5, 0), (7.5, 7.5), ("7", 7), (10, 10), (0, 0)])
def test_normalize_vote_clamps_scores(raw, expected):
    v = validate_rule.normalize_vote({"score": raw, "approve": True})
    assert v["valid"] is True and v["score"] == expected


@pytest.mark.parametrize("raw", [None, "text", [1], 5, ["a"]])
def test_normalize_vote_non_dict_is_invalid(raw):
    v = validate_rule.normalize_vote(raw)
    assert v["valid"] is False and v["approve"] is False


def test_normalize_vote_coerces_issues_and_reasoning():
    v = validate_rule.normalize_vote({"score": 5, "approve": False, "issues": "single", "reasoning": ["x"]})
    assert v["issues"] == ["single"] and isinstance(v["reasoning"], str)
    v = validate_rule.normalize_vote({"score": 5, "approve": False, "issues": None, "reasoning": None})
    assert v["issues"] == [] and v["reasoning"] == ""


def test_normalize_vote_honours_parser_invalid_marker():
    v = validate_rule.normalize_vote(validate_rule.parse_llm_response("not json at all"))
    assert v["valid"] is False and v["approve"] is False


def test_one_voter_with_string_false_cannot_approve(monkeypatch):
    monkeypatch.setattr(validate_rule, "ask_ollama", lambda r, q: {"score": 9, "approve": "false"})
    monkeypatch.setattr(validate_rule, "ask_claude", lambda r, q: OK)
    monkeypatch.setattr(validate_rule, "ask_gemini", lambda r, q: {**OK, "approve": False, "score": 3})
    approvals, avg, fb = validate_rule.validate_rule_text("r", "q")
    assert approvals == 2 - 1 and fb["Ollama"]["approve"] is False
    assert validate_rule.passes(approvals, avg, 5, None, validate_rule.count_valid(fb)) is False


def test_non_numeric_score_does_not_crash_the_run(monkeypatch):
    monkeypatch.setattr(validate_rule, "ask_ollama", lambda r, q: {"score": "abc", "approve": True})
    monkeypatch.setattr(validate_rule, "ask_claude", lambda r, q: OK)
    monkeypatch.setattr(validate_rule, "ask_gemini", lambda r, q: OK)
    approvals, avg, fb = validate_rule.validate_rule_text("r", "q")
    assert approvals == 2
    assert fb["Ollama"]["valid"] is False and fb["Ollama"]["score"] == 0
    assert validate_rule.count_valid(fb) == 2
    assert avg == pytest.approx((8 + 8 + 0) / 3)  # malformed output counts as 0, never silently dropped


def test_injected_huge_score_is_clamped(monkeypatch):
    monkeypatch.setattr(validate_rule, "ask_ollama", lambda r, q: {"score": 1000, "approve": True})
    monkeypatch.setattr(validate_rule, "ask_claude", lambda r, q: {**OK, "score": 3, "approve": False})
    monkeypatch.setattr(validate_rule, "ask_gemini", lambda r, q: {**OK, "score": 3, "approve": False})
    approvals, avg, fb = validate_rule.validate_rule_text("r", "q")
    assert fb["Ollama"]["score"] == 10
    assert avg == pytest.approx(16 / 3) and avg < 6


@pytest.mark.parametrize("exc", [AttributeError("list has no get"), TypeError("x"), RuntimeError("y"),
                                 ZeroDivisionError(), requests.ConnectionError("nope"), KeyError("k")])
def test_any_voter_exception_is_logged_and_voter_excluded(monkeypatch, caplog, exc):
    def boom(r, q):
        raise exc
    monkeypatch.setattr(validate_rule, "ask_ollama", boom)
    monkeypatch.setattr(validate_rule, "ask_claude", lambda r, q: OK)
    monkeypatch.setattr(validate_rule, "ask_gemini", lambda r, q: OK)
    with caplog.at_level("WARNING"):
        approvals, avg, fb = validate_rule.validate_rule_text("r", "q")
    assert "Ollama" not in fb and set(fb) == {"Claude", "Gemini"}
    assert approvals == 2 and avg == 8  # excluded from the average, not scored 0
    assert any("Ollama" in r.getMessage() for r in caplog.records)


def test_voter_returning_a_list_is_invalid_not_a_crash(monkeypatch):
    monkeypatch.setattr(validate_rule, "ask_ollama", lambda r, q: [1, 2])
    monkeypatch.setattr(validate_rule, "ask_claude", lambda r, q: OK)
    monkeypatch.setattr(validate_rule, "ask_gemini", lambda r, q: OK)
    approvals, avg, fb = validate_rule.validate_rule_text("r", "q")
    assert fb["Ollama"]["valid"] is False and approvals == 2


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


def test_voter_past_deadline_is_excluded(monkeypatch, caplog):
    monkeypatch.setattr(validate_rule, "VOTER_DEADLINE", 0.3)
    monkeypatch.setattr(validate_rule, "ask_ollama", lambda r, q: (time.sleep(1.0), OK)[1])
    monkeypatch.setattr(validate_rule, "ask_claude", lambda r, q: OK)
    monkeypatch.setattr(validate_rule, "ask_gemini", lambda r, q: OK)
    t0 = time.monotonic()
    with caplog.at_level("WARNING"):
        approvals, avg, fb = validate_rule.validate_rule_text("r", "q")
    assert time.monotonic() - t0 < 0.9
    assert set(fb) == {"Claude", "Gemini"}
    assert any("Ollama" in r.getMessage() for r in caplog.records)


# -- parse_llm_response / lint -------------------------------------------------------

def test_parse_llm_response_plain_and_fenced_json():
    assert validate_rule.parse_llm_response('{"score": 7, "approve": true}')["score"] == 7
    fenced = '```json\n{"score": 6, "approve": false, "issues": ["x"]}\n```'
    assert validate_rule.parse_llm_response(fenced) == {"score": 6, "approve": False, "issues": ["x"]}


def test_parse_llm_response_json_embedded_in_prose():
    out = validate_rule.parse_llm_response('Sure! Here you go: {"score": 9, "approve": true} hope it helps')
    assert out["score"] == 9 and out["approve"] is True


@pytest.mark.parametrize("text", ["not json", "", None, "[1,2,3]", '"just a string"', 42])
def test_parse_llm_response_garbage_is_a_rejection_marked_invalid(text):
    out = validate_rule.parse_llm_response(text)
    assert out["approve"] is False and out.get("invalid") is True
    assert out["issues"]


def test_lint_accepts_valid_rule():
    assert validate_rule.lint_sigma_yaml(RULE) == (True, "OK")


def test_lint_reports_yaml_syntax_error():
    ok, msg = validate_rule.lint_sigma_yaml("title: [unclosed\n  : :")
    assert ok is False and "YAML syntax error" in msg


def test_lint_rejects_non_mapping():
    ok, msg = validate_rule.lint_sigma_yaml("- a\n- b\n")
    assert ok is False and "mapping" in msg


def test_lint_lists_missing_fields():
    ok, msg = validate_rule.lint_sigma_yaml("title: t\nid: 1\n")
    assert ok is False and "logsource" in msg and "detection" in msg and "title" not in msg


def test_validate_prompt_with_braces_in_rule_does_not_raise():
    rule = "title: {x} {{y}} {0} ${z} %s"
    q = 'a:{"b"} $query'
    prompt = validate_rule.build_validation_prompt(rule, q)
    assert rule in prompt and q in prompt
    heal = validate_rule.build_heal_prompt(rule, q, "info {b}", "fb {c}", 2)
    assert rule in heal and "info {b}" in heal and "fb {c}" in heal


def test_ecs_pipeline_is_shared_not_duplicated():
    assert not hasattr(validate_rule, "_ecs_fieldmap_pipeline")


# -- heal prompt: ECS field list comes from lab/ecs.py --------------------------------------

def _ecs_mapped_fields():
    out = set()
    for item in ecs.pipeline().items:
        mapping = getattr(item.transformation, "mapping", None)
        if mapping:
            out.update(v for v in mapping.values() if isinstance(v, str))
    return out


def test_heal_prompt_field_list_is_generated_from_lab_ecs():
    prompt = validate_rule.build_heal_prompt("r", "q", "b", "f", 1)
    mapped = _ecs_mapped_fields()
    assert "destination.ip" in mapped
    for field in mapped:
        assert field in prompt, field
    assert "network.destination.ip" not in prompt


def test_ecs_field_names_follow_the_mapping(monkeypatch):
    names = validate_rule.ecs_field_names()
    assert set(names) >= _ecs_mapped_fields() and names == sorted(set(names))
    real = ecs.pipeline

    def patched():
        p = real()
        for item in p.items:
            if hasattr(item.transformation, "mapping"):
                item.transformation.mapping["Foo"] = "brand.new.field"
        return p
    monkeypatch.setattr(ecs, "pipeline", patched)
    assert "brand.new.field" in validate_rule.build_heal_prompt("r", "q", "b", "f", 1)


def test_describe_backtest_mentions_deploy_indices_and_noise():
    ok = validate_rule.describe_backtest(5, None)
    assert "5 hits" in ok and all(i in ok for i in INDICES)
    zero = validate_rule.describe_backtest(0, None)
    assert "0 hits" in zero
    noisy = validate_rule.describe_backtest(validate_rule.MAX_BACKTEST_HITS + 1, None)
    assert "too many" in noisy.lower() and "narrow" in noisy.lower()
    assert "ES down" in validate_rule.describe_backtest(0, "ES down")


# -- heal invariants: same id, same technique tag ---------------------------------------

def test_heal_invariants_accept_same_id_and_tags():
    healed = RULE.replace("status: test", "status: experimental").replace("powershell.exe", "pwsh.exe")
    assert validate_rule.check_heal_invariants(RULE, healed) == (True, "OK")


def test_heal_invariants_reject_changed_id():
    healed = RULE.replace(RULE_ID, "99999999-2222-3333-4444-555555555555")
    ok, why = validate_rule.check_heal_invariants(RULE, healed)
    assert ok is False and "id" in why


def test_heal_invariants_reject_changed_or_dropped_technique_tag():
    ok, why = validate_rule.check_heal_invariants(RULE, RULE.replace("attack.t1059.001", "attack.t1003.001"))
    assert ok is False and "technique" in why
    ok, _ = validate_rule.check_heal_invariants(RULE, RULE.replace("    - attack.t1059.001\n", ""))
    assert ok is False


def test_heal_invariants_technique_tag_case_insensitive():
    assert validate_rule.check_heal_invariants(RULE, RULE.replace("attack.t1059.001", "attack.T1059.001"))[0]


def test_heal_invariants_reject_unparseable_healed_rule():
    assert validate_rule.check_heal_invariants(RULE, "title: [unclosed")[0] is False
    assert validate_rule.check_heal_invariants(RULE, "- a\n- b\n")[0] is False


def test_heal_invariants_with_unparseable_original_use_text_fallback():
    broken = RULE.replace("detection:", "detection: [")  # invalid YAML but id/tag still in text
    assert validate_rule.check_heal_invariants(broken, RULE)[0] is True
    assert validate_rule.check_heal_invariants(broken, RULE.replace(RULE_ID, "other-id"))[0] is False


def test_heal_invariants_original_without_id_or_tag_imposes_nothing():
    bare = "title: t\nlogsource: {category: x}\ndetection: {condition: s}\n"
    assert validate_rule.check_heal_invariants(bare, RULE)[0] is True


# -- main() flows -------------------------------------------------------------------

class Harness:
    def __init__(self, tmp_path, monkeypatch):
        self.path = tmp_path / "rule.yml"
        self.path.write_text(RULE, encoding="utf-8")
        self.mp = monkeypatch
        self.backtest_calls, self.heal_calls, self.vote_texts = [], [], []
        self.emails, self.saved = [], []
        self.backtests = [(5, None)]
        self.votes = [(3, 9.0, {"Claude": OK, "Gemini": OK, "Ollama": OK})]
        self.heals = []
        monkeypatch.setattr(sys, "argv", ["validate_rule.py", str(self.path)])
        monkeypatch.setattr(validate_rule, "convert_sigma", lambda p: "q")
        monkeypatch.setattr(validate_rule, "convert_sigma_text", lambda t: "q")
        monkeypatch.setattr(validate_rule, "backtest_query", self._backtest)
        monkeypatch.setattr(validate_rule, "validate_rule_text", self._vote)
        monkeypatch.setattr(validate_rule, "heal_rule", self._heal)
        monkeypatch.setattr(validate_rule, "send_circuit_breaker_email",
                            lambda *a, **k: self.emails.append(a))
        monkeypatch.setattr(validate_rule, "save_validation", lambda *a, **k: self.saved.append(a))
        monkeypatch.setattr(validate_rule.time, "sleep", lambda s: None)

    @staticmethod
    def _pick(seq, i):
        return seq[min(i, len(seq) - 1)]

    def _backtest(self, q):
        self.backtest_calls.append(q)
        return self._pick(self.backtests, len(self.backtest_calls) - 1)

    def _vote(self, text, q):
        self.vote_texts.append(text)
        return self._pick(self.votes, len(self.vote_texts) - 1)

    def _heal(self, text, query, hits, feedback, attempt):
        self.heal_calls.append((text, query, hits, attempt))
        return self._pick(self.heals, len(self.heal_calls) - 1)

    def run(self):
        with pytest.raises(SystemExit) as ei:
            validate_rule.main()
        return ei.value.code


FAIL_VOTE = (1, 4.0, {"Claude": {**OK, "approve": False, "score": 4}, "Gemini": OK,
                      "Ollama": {**OK, "approve": False, "score": 1}})


def test_pass_path_first_attempt_saves_and_leaves_file_alone(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    assert h.run() == 0
    assert h.path.read_text(encoding="utf-8") == RULE
    assert len(h.saved) == 1 and h.saved[0][-1] == "approved"
    assert h.emails == [] and h.heal_calls == []


def test_healed_rule_is_written_back_on_pass(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    healed = RULE.replace("status: test", "status: experimental")
    h.votes = [FAIL_VOTE, (3, 9.0, {"Claude": OK, "Gemini": OK, "Ollama": OK})]
    h.heals = [healed]
    assert h.run() == 0
    assert h.path.read_text(encoding="utf-8") == healed
    assert h.vote_texts == [RULE, healed]
    assert h.saved[-1][-1] == "approved"


def test_heal_that_changes_the_id_is_rejected_and_never_written(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    h.votes = [FAIL_VOTE]
    h.heals = [RULE.replace(RULE_ID, "99999999-2222-3333-4444-555555555555")]
    assert h.run() == 1
    assert h.path.read_text(encoding="utf-8") == RULE
    assert h.vote_texts == [RULE, RULE, RULE]  # the rejected rewrite was never validated or adopted
    assert len(h.emails) == 1 and h.saved[-1][-1] == "failed"


def test_heal_that_changes_technique_tag_is_rejected(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    h.votes = [FAIL_VOTE, (3, 9.0, {"Claude": OK, "Gemini": OK, "Ollama": OK})]
    h.heals = [RULE.replace("attack.t1059.001", "attack.t1003.001")]
    assert h.run() == 0  # attempt 2 passes, but on the ORIGINAL text
    assert h.path.read_text(encoding="utf-8") == RULE
    assert h.vote_texts[1] == RULE


def test_es_down_exits_through_backtest_path_not_lint(tmp_path, monkeypatch, capsys):
    h = Harness(tmp_path, monkeypatch)
    h.backtests = [(0, "ES down")]
    h.heals = [RULE.replace("status: test", "status: experimental")]  # valid, same id/tag
    assert h.run() == 1
    out = capsys.readouterr().out
    assert "YAML lint FAILED" not in out and "Backtest FAILED: ES down" in out
    assert len(h.backtest_calls) == 3
    assert all(c[1] == "q" for c in h.heal_calls) and len(h.heal_calls) == 2
    assert len(h.emails) == 1 and h.emails[0][1] == 3
    assert h.saved[-1][-1] == "failed"


def test_noisy_rule_fails_even_with_unanimous_approval(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    h.backtests = [(validate_rule.MAX_BACKTEST_HITS + 1, None)]
    h.heals = [RULE.replace("status: test", "status: experimental")]
    assert h.run() == 1
    assert h.heal_calls and h.heal_calls[0][2] == validate_rule.MAX_BACKTEST_HITS + 1


def test_single_valid_voter_fails_quorum(tmp_path, monkeypatch, capsys):
    h = Harness(tmp_path, monkeypatch)
    h.votes = [(1, 9.0, {"Claude": OK})]
    h.heals = [RULE.replace("status: test", "status: experimental")]
    assert h.run() == 1
    assert "quorum" in capsys.readouterr().out


def test_lint_failure_path_still_heals_and_circuit_breaks(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    h.path.write_text("title: only\n", encoding="utf-8")
    h.heals = ["title: still broken\n"]
    assert h.run() == 1
    assert h.backtest_calls == [] and len(h.emails) == 1


def test_lint_heal_with_new_id_is_not_adopted(tmp_path, monkeypatch):
    # original has an id and tag but is missing logsource; the healer must not swap them
    broken = RULE.replace("logsource:\n    category: process_creation\n    product: windows\n", "")
    h = Harness(tmp_path, monkeypatch)
    h.path.write_text(broken, encoding="utf-8")
    h.heals = [RULE.replace(RULE_ID, "99999999-2222-3333-4444-555555555555")]
    assert h.run() == 1
    assert h.path.read_text(encoding="utf-8") == broken
    assert h.vote_texts == []


# -- emails: every model/log-derived field is HTML-escaped --------------------------------

class FakeSMTP:
    sent = []

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        pass

    def login(self, user, pw):
        pass

    def send_message(self, msg):
        FakeSMTP.sent.append(msg)


def _html_of(msg):
    return msg.get_body(preferencelist=("html",)).get_content()


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.sent = []
    monkeypatch.setattr(validate_rule.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("SMTP_HOST", "smtp.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_FROM", "a@test")
    monkeypatch.setenv("SMTP_TO", "b@test")
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SF_REPO_URL", raising=False)
    return FakeSMTP


def test_circuit_breaker_email_escapes_model_and_log_derived_text(smtp):
    evil = '<script>alert(1)</script><a href="http://evil.test/phish">Click to approve</a>'
    history = [{
        "<b>Claude</b>": {"score": "<img src=x onerror=alert(1)>", "approve": True, "reasoning": evil},
        "Gemini": {"score": 3, "approve": False, "reasoning": ["<i>list</i>"]},
    }]
    validate_rule.send_circuit_breaker_email("detections/sigma/<h1>pwn</h1>.yml", 3, history)
    assert len(smtp.sent) == 1
    html = _html_of(smtp.sent[0])
    for raw in ("<script>", "<img src=x", 'href="http://evil.test', "<h1>pwn", "<b>Claude</b>", "<i>list</i>"):
        assert raw not in html, raw
    assert "&lt;script&gt;" in html and "&lt;img src=x" in html
    assert "&lt;b&gt;Claude&lt;/b&gt;" in html
    assert "&lt;h1&gt;pwn&lt;/h1&gt;" in html  # rule path and derived title are escaped too


def test_circuit_breaker_email_without_smtp_config_is_skipped(smtp, monkeypatch):
    monkeypatch.delenv("SMTP_HOST")
    validate_rule.send_circuit_breaker_email("r.yml", 3, [])
    assert smtp.sent == []


def test_circuit_breaker_email_escapes_repo_url(smtp, monkeypatch):
    monkeypatch.setenv("SF_REPO_URL", 'https://x.test/"><script>1</script>')
    validate_rule.send_circuit_breaker_email("r.yml", 3, [])
    assert "<script>" not in _html_of(smtp.sent[0])


# -- LLM voters: no silent POST retries ---------------------------------------------------

@pytest.fixture
def llm_server():
    state = {"hits": []}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            state["hits"].append(self.path)
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{srv.server_port}"
    try:
        yield state
    finally:
        srv.shutdown()


def test_ollama_post_is_not_retried_on_server_error(llm_server, monkeypatch):
    monkeypatch.setenv("OLLAMA_URL", llm_server["url"])
    with pytest.raises(requests.HTTPError):
        validate_rule.ask_ollama("rule", "query")
    assert len(llm_server["hits"]) == 1


@responses.activate
def test_all_llm_calls_use_sessions_without_post_retry(monkeypatch):
    kwargs_seen = []
    real = validate_rule.make_session

    def spy(*a, **k):
        kwargs_seen.append(k)
        return real(*a, **k)
    monkeypatch.setattr(validate_rule, "make_session", spy)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a")
    monkeypatch.setenv("GEMINI_API_KEY", "g")
    monkeypatch.setenv("OLLAMA_URL", "http://ollama.test")
    good = '{"score": 8, "approve": true}'
    responses.add(responses.POST, "http://ollama.test/api/generate", json={"response": good})
    responses.add(responses.POST, "https://api.anthropic.com/v1/messages", json={"content": [{"text": good}]})
    responses.add(responses.POST, "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
                  json={"candidates": [{"content": {"parts": [{"text": good}]}}]})
    validate_rule.ask_ollama("r", "q")
    validate_rule.ask_claude("r", "q")
    validate_rule.ask_gemini("r", "q")
    validate_rule.heal_rule(RULE, "q", 0, {}, 1)
    assert len(kwargs_seen) == 4
    assert not any(k.get("retry_post") for k in kwargs_seen)


@responses.activate
def test_gemini_error_payload_excludes_voter_instead_of_scoring(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g")
    responses.add(responses.POST, "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
                  json={"error": {"code": 429}}, status=200)
    with pytest.raises(Exception) as ei:
        validate_rule.ask_gemini("r", "q")
    assert not isinstance(ei.value, validate_rule.MissingApiKey)


def test_validate_fails_when_es_unreachable(tmp_path, monkeypatch):
    # kept from the original suite: the whole run must exit 1 when ES is down
    h = Harness(tmp_path, monkeypatch)
    h.backtests = [(0, "ES down")]
    h.heals = ["x" * 200]
    assert h.run() == 1
