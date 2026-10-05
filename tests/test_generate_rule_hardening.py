"""Hardening tests for generate_rule: main() end to end (no RecursionError) and
Elasticsearch-error handling. Everything external is faked (offline)."""
import json
from types import SimpleNamespace

import pytest
import yaml

import generate_rule as gr
from lab.es import SearchError

ANALYSIS = {
    "technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "execution",
    "already_covered": False, "confidence": "high", "severity": "high",
    "false_positive_risk": "low", "detection_focus": "encoded powershell",
    "key_indicators": ["powershell -enc"], "reasoning": "r", "plain_english_summary": "s",
    "next_simulation": "T1049 — Discovery — gap",
}

GOOD_SIGMA = {
    "title": "Encoded PowerShell", "id": "00000000-0000-0000-0000-000000000000",
    "status": "experimental", "author": "evil", "date": "1999/01/01", "level": "high",
    "tags": ["attack.execution", "attack.t1059.001"],
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {"selection": {"process.name": "powershell.exe"}, "condition": "selection"},
}


def dump(**over):
    d = dict(GOOD_SIGMA)
    d.update(over)
    return yaml.safe_dump({k: v for k, v in d.items() if v is not None}, sort_keys=False)


class FakeClient:
    def __init__(self, texts):
        self.texts = list(texts)
        self.calls = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kw):
        self.calls.append(kw)
        text = self.texts.pop(0) if len(self.texts) > 1 else self.texts[0]
        return SimpleNamespace(content=[SimpleNamespace(text=text)])


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(gr, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(gr, "HERE", tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("SF_AUTHOR", "Tester")
    monkeypatch.delenv("WATER_REVIEW_GATE", raising=False)
    monkeypatch.delenv("MODEL_NAME", raising=False)
    gr.get_client.cache_clear()
    yield
    monkeypatch.undo()  # restore the real (lru_cached) get_client before clearing it
    gr.get_client.cache_clear()


# ---------------------------------------------------------------- ES error
def test_query_elasticsearch_propagates_search_error(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://es.test:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "k")

    def boom(*a, **k):
        raise SearchError("401")
    monkeypatch.setattr(gr, "search_all", boom)
    with pytest.raises(SearchError):
        gr.query_elasticsearch(60)


# ---------------------------------------------------------------- main() end to end
class World:
    def __init__(self, monkeypatch, tmp_path, texts, events=None, es_error=False, last=None):
        self.git, self.emails, self.runs = [], [], []
        monkeypatch.setattr(gr, "_git", lambda *a: self.git.append(a))
        monkeypatch.setattr(gr, "_commit", lambda m: self.git.append(("commit", m)) or True)
        monkeypatch.setattr(gr.subprocess, "run", lambda cmd, **k: self.runs.append(cmd))
        monkeypatch.setattr(gr, "send_email", lambda s, h: self.emails.append((s, h)))
        monkeypatch.setattr(gr, "process_hunt_triggered_verdicts", lambda **k: 0)
        monkeypatch.setattr(gr, "should_send_weekly_digest", lambda d: False)
        monkeypatch.setattr(gr, "write_ai_context", lambda a: "ctx")
        self.client = FakeClient(texts)
        monkeypatch.setattr(gr, "get_client", lambda: self.client)

        def q(lookback):
            if es_error:
                raise SearchError("down")
            if events is not None:
                return events
            return [{"process.name": "powershell.exe", "event.code": "1", "host.name": "h"}]
        monkeypatch.setattr(gr, "query_elasticsearch", q)
        if last:
            (tmp_path / "state").mkdir(exist_ok=True)
            (tmp_path / "state" / "last_run.json").write_text(json.dumps(last))

    def state(self, name):
        return json.loads((gr.STATE_DIR / name).read_text())


def run_main():
    with pytest.raises(SystemExit) as ei:
        gr.main()
    return ei.value.code


def test_main_deploy_path_runs_end_to_end(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path, [json.dumps(ANALYSIS), dump()])
    gr.main()  # must not recurse or raise
    assert len(list((tmp_path / "detections" / "sigma").glob("*.yml"))) == 1
    assert w.state("seen_techniques.json")["T1059.001"]["rule_id"]
    assert w.state("hunt_log.json")[-1]["result"] == "deployed"
    assert sum(1 for c in w.git if c == ("push",)) == 2  # rule push + state push
    assert any("generate_heatmap.py" in str(c) for c in w.runs)
    assert w.emails


def test_main_review_gate_path_runs_end_to_end(monkeypatch, tmp_path):
    monkeypatch.setenv("WATER_REVIEW_GATE", "true")
    w = World(monkeypatch, tmp_path, [json.dumps(ANALYSIS), dump()])
    gr.main()
    assert not list((tmp_path / "detections" / "sigma").glob("*.yml"))
    assert w.state("pending_rules.json")[0]["technique_id"] == "T1059.001"
    assert w.state("hunt_log.json")[-1]["result"] == "pending_review"
    assert ("push",) in w.git and "[Review needed]" in w.emails[0][0]


def test_main_nothing_new_path_runs_end_to_end(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path, [json.dumps(dict(ANALYSIS, already_covered=True))])
    gr.main()
    assert w.state("hunt_log.json")[-1]["result"] == "already_covered"
    assert ("push",) in w.git and w.emails
    assert not (tmp_path / "detections" / "sigma").exists()


def test_main_no_events_still_exits_zero_and_advances_last_run(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path, ["x"], events=[])
    assert run_main() == 0
    assert w.state("last_run.json")["timestamp"]
    assert w.state("hunt_log.json")[-1]["result"] == "no_events"
    assert ("push",) in w.git


def test_main_es_error_exits_nonzero_and_does_not_advance_last_run(monkeypatch, tmp_path, caplog):
    w = World(monkeypatch, tmp_path, ["x"], es_error=True,
              last={"timestamp": "2026-01-01T00:00:00+00:00"})
    with caplog.at_level("ERROR"):
        code = run_main()
    assert code not in (0, None)
    assert w.state("last_run.json")["timestamp"] == "2026-01-01T00:00:00+00:00"
    log_path = gr.STATE_DIR / "hunt_log.json"
    entries = json.loads(log_path.read_text()) if log_path.exists() else []
    assert not any(e.get("result") == "no_events" for e in entries)
    assert caplog.records


def test_main_push_failure_is_surfaced_not_recursive(monkeypatch, tmp_path):
    World(monkeypatch, tmp_path, [json.dumps(dict(ANALYSIS, already_covered=True))])

    def bad(*a):
        raise gr.GitError("rejected")
    monkeypatch.setattr(gr, "_git", bad)
    gr.main()  # GitError swallowed with a loud log; no RecursionError
