import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import responses
import yaml

import generate_rule

ROOT = Path(__file__).resolve().parent.parent
ANALYSIS = {"technique_id": "T1059", "technique_name": "Command Interpreter", "tactic": "execution",
            "already_covered": False, "confidence": "high", "detection_focus": "f",
            "key_indicators": ["a"], "reasoning": "r"}

VALID_SIGMA = yaml.safe_dump({
    "title": "Command Interpreter Use",
    "logsource": {"category": "process_creation", "product": "windows"},
    "tags": ["attack.execution", "attack.t1059"], "level": "medium",
    "detection": {"selection": {"process.name": "cmd.exe"}, "condition": "selection"},
}, sort_keys=False)


class FakeClient:
    def __init__(self, texts):
        self.texts = list(texts)
        self.calls = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kw):
        self.calls.append(kw)
        text = self.texts.pop(0) if len(self.texts) > 1 else self.texts[0]
        return SimpleNamespace(content=[SimpleNamespace(text=text)])


class RoutingClient(FakeClient):
    """Answers each stage with the right shape: analysis JSON, Sigma YAML, or a context sentence."""
    def __init__(self, *a, **k):
        super().__init__(["unused"])

    def _create(self, **kw):
        self.calls.append(kw)
        prompt = kw["messages"][0]["content"]
        text = (VALID_SIGMA if "writing a Sigma rule" in prompt
                else json.dumps(ANALYSIS) if "Return JSON only" in prompt else "context sentence")
        return SimpleNamespace(content=[SimpleNamespace(text=text)])


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(generate_rule, "STATE_DIR", tmp_path / "state")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("MODEL_NAME", raising=False)
    generate_rule.get_client.cache_clear()
    yield
    getattr(generate_rule.get_client, "cache_clear", lambda: None)()


def test_generate_malformed_llm_json_is_retried_once_then_queued_as_failed(monkeypatch):
    fake = FakeClient(["this is not json", "still { not json"])
    monkeypatch.setattr(generate_rule, "get_client", lambda: fake)
    out = generate_rule.analyze_or_queue_failed({"processes": ["a"]}, 5, {}, 60, "2026-01-01T00:00:00+00:00")
    assert out is None
    assert len(fake.calls) == 2  # exactly one retry
    failed = json.loads((generate_rule.STATE_DIR / "failed_rules.json").read_text())
    assert len(failed) == 1 and failed[0]["stage"] == "analysis"
    assert "still { not json" in failed[0]["raw"]


def test_generate_malformed_then_valid_json_succeeds_on_retry(monkeypatch):
    fake = FakeClient(["garbage", "```json\n" + json.dumps(ANALYSIS) + "\n```"])
    monkeypatch.setattr(generate_rule, "get_client", lambda: fake)
    out = generate_rule.analyze_or_queue_failed({}, 5, {}, 60, "t")
    assert out["technique_id"] == "T1059"
    assert len(fake.calls) == 2
    assert not (generate_rule.STATE_DIR / "failed_rules.json").exists()


def test_generate_reuses_one_anthropic_client(monkeypatch):
    made = []

    class Counting(RoutingClient):
        def __init__(self, *a, **k):
            made.append(1)
            super().__init__()
    monkeypatch.setattr(generate_rule.anthropic, "Anthropic", Counting)
    generate_rule.analyze_with_claude({}, 1, {}, 60)
    generate_rule.analyze_with_claude({}, 1, {}, 60)
    generate_rule.generate_sigma_rule({}, ANALYSIS)
    generate_rule.write_ai_context(ANALYSIS)
    assert len(made) == 1


def test_model_name_comes_from_env(monkeypatch):
    monkeypatch.setenv("MODEL_NAME", "my-test-model")
    fake = RoutingClient()
    monkeypatch.setattr(generate_rule, "get_client", lambda: fake)
    generate_rule.analyze_with_claude({}, 1, {}, 60)
    generate_rule.generate_sigma_rule({}, ANALYSIS)
    generate_rule.write_ai_context(ANALYSIS)
    assert [c["model"] for c in fake.calls] == ["my-test-model"] * 3


def test_model_name_has_default():
    assert generate_rule.model_name()


def test_is_valid_sigma_parses_yaml_not_substrings():
    good = ("title: t\nid: 1\nlogsource:\n  category: process_creation\n"
            "detection:\n  selection:\n    a: b\n  condition: selection\n")
    assert generate_rule.is_valid_sigma(good)
    # all the old substrings present, but not a real rule
    fake = "# title: id: logsource: detection: condition:\nfoo: bar\n"
    assert not generate_rule.is_valid_sigma(fake)
    assert not generate_rule.is_valid_sigma("title: [unclosed")
    assert not generate_rule.is_valid_sigma(good.replace("  condition: selection\n", ""))


def test_save_and_push_surfaces_git_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(generate_rule, "SIGMA_OUTPUT_DIR", str(tmp_path / "sigma"))

    def fail(cmd, **kw):
        raise subprocess.CalledProcessError(1, cmd, stderr=b"rejected")
    monkeypatch.setattr(generate_rule.subprocess, "run", fail)
    with pytest.raises(generate_rule.GitError):
        generate_rule.save_and_push("title: x\n", ANALYSIS, "r" * 36)
    assert list((tmp_path / "sigma").glob("*.yml"))  # file was still written


def test_git_commands_use_timeout_and_check(tmp_path, monkeypatch):
    monkeypatch.setattr(generate_rule, "SIGMA_OUTPUT_DIR", str(tmp_path / "sigma"))
    seen = []

    def ok(cmd, **kw):
        seen.append(kw)
        return SimpleNamespace(stdout="", stderr="", returncode=0)
    monkeypatch.setattr(generate_rule.subprocess, "run", ok)
    generate_rule.save_and_push("title: x\n", ANALYSIS, "r" * 36)
    assert seen and all(kw.get("timeout") and kw.get("check") for kw in seen)


def test_queue_for_review_roundtrip_and_corrupt_state(tmp_path, monkeypatch):
    monkeypatch.setattr(generate_rule, "HERE", tmp_path)
    monkeypatch.setattr(generate_rule, "write_ai_context", lambda a: "ctx")
    generate_rule.queue_for_review("title: x\n", ANALYSIS, "rid-1", "now")
    generate_rule.queue_for_review("title: y\n", ANALYSIS, "rid-2", "now")
    items = json.loads((tmp_path / "state" / "pending_rules.json").read_text())
    assert [i["rule_id"] for i in items] == ["rid-1", "rid-2"]
    (tmp_path / "state" / "pending_rules.json").write_text("{broken")
    from lab.state import StateCorrupt
    with pytest.raises(StateCorrupt):
        generate_rule.queue_for_review("title: z\n", ANALYSIS, "rid-3", "now")


def test_state_roundtrip_and_corrupt_state_raises():
    generate_rule.save_state({"T1": {}}, {"timestamp": "x"}, [{"a": 1}], {"week_start": None})
    seen, last, log, digest = generate_rule.load_state()
    assert seen == {"T1": {}} and last == {"timestamp": "x"} and log == [{"a": 1}]
    (generate_rule.STATE_DIR / "hunt_log.json").write_text("[[")
    from lab.state import StateCorrupt
    with pytest.raises(StateCorrupt):
        generate_rule.load_state()


@responses.activate
def test_query_elasticsearch_pages_past_100_events(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://es.test:9200")
    page1 = [{"_source": {"i": i}, "sort": [i, i]} for i in range(500)]
    page2 = [{"_source": {"i": i}, "sort": [i, i]} for i in range(500, 650)]
    responses.add(responses.POST, "https://es.test:9200/logs-*/_search", json={"hits": {"hits": page1}})
    responses.add(responses.POST, "https://es.test:9200/logs-*/_search", json={"hits": {"hits": page2}})
    events = generate_rule.query_elasticsearch(60)
    assert len(events) == 650


@responses.activate
def test_query_elasticsearch_error_raises_and_logs(monkeypatch, caplog):
    monkeypatch.setenv("ELASTIC_URL", "https://es.test:9200")
    responses.add(responses.POST, "https://es.test:9200/logs-*/_search", status=401, json={})
    with caplog.at_level("ERROR"):
        with pytest.raises(generate_rule.SearchError):
            generate_rule.query_elasticsearch(60)
    assert caplog.records


def test_generate_prompt_author_not_hardcoded(monkeypatch):
    fake = FakeClient([VALID_SIGMA])
    monkeypatch.setattr(generate_rule, "get_client", lambda: fake)
    monkeypatch.setenv("SF_AUTHOR", "Jahsean Meikle")
    generate_rule.generate_sigma_rule({}, ANALYSIS)
    prompt = fake.calls[0]["messages"][0]["content"]
    assert "author: Jahsean Meikle" in prompt and "1x" "LoZec" not in prompt


def test_no_legacy_branding_or_lab_ip_in_pipeline_scripts():
    pat = re.compile(r"1x" r"lozec|ta" r"llkitchen|ta" r"ll kitchen|al" r"bundy|10\.0\.0\.1|tk-hunt|verify\s*=\s*False", re.I)
    for name in ("generate_rule.py", "validate_rule.py", "deploy_rule.py", "approve.py"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert not pat.search(text), f"legacy string in {name}: {pat.search(text).group(0)}"


def test_empty_sf_author_env_falls_back_to_default(monkeypatch):
    """`cp .env.example .env` with SF_AUTHOR= left blank must not blank the rule author."""
    fake = FakeClient([VALID_SIGMA])
    monkeypatch.setattr(generate_rule, "get_client", lambda: fake)
    monkeypatch.setenv("SF_AUTHOR", "")
    generate_rule.generate_sigma_rule({}, ANALYSIS)
    prompt = fake.calls[0]["messages"][0]["content"]
    assert "author: SentinelForge" in prompt


def test_env_example_optional_variables_are_commented_out():
    from pathlib import Path
    text = (Path(__file__).resolve().parent.parent / ".env.example").read_text(encoding="utf-8")
    for var in ("LAB_ADMIN_TOKEN", "SF_LAB_DIR", "SF_LOG_DIR", "SF_AUTHOR", "SF_REPO_URL", "MODEL_NAME"):
        assert f"# {var}=" in text, var
        assert f"\n{var}=" not in text, f"{var} must not be set empty by default"
