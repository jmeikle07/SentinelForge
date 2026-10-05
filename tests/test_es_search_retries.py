"""Elasticsearch _search/_count are POSTs but read-only, so they must keep their 429/5xx retries
after lab.http stopped retrying POSTs by default (an LLM call or an indexed document must not be
re-sent, but a search can be). Indexing a document must stay non-retrying (a retry can duplicate)."""
import json

import pytest
import responses

import generate_rule
import rule_efficacy
import sf_hunt
import water_hunt_trigger
from lab import http

ES = "https://es.test:9200"


@pytest.fixture
def spy(monkeypatch):
    """Record the kwargs of every lab.http.session() call (and of generate_rule.make_session)."""
    calls = []
    real = http.session

    def recording(*a, **k):
        calls.append(k)
        return real(*a, **{**k, "retries": 0})

    monkeypatch.setattr(http, "session", recording)
    monkeypatch.setattr(generate_rule, "make_session", recording)
    monkeypatch.setenv("ELASTIC_URL", ES)
    monkeypatch.setenv("ELASTIC_API_KEY", "k")
    return calls


@responses.activate
def test_sf_hunt_search_retries_posts_but_indexing_does_not(spy):
    responses.add(responses.POST, f"{ES}/idx/_search", json={"hits": {"hits": []}})
    responses.add(responses.POST, f"{ES}/idx/_doc", json={"result": "created"})
    sf_hunt.elk_search("idx", {"query": {"match_all": {}}})
    assert spy[-1].get("retry_post") is True
    sf_hunt.elk_index_doc("idx", {"a": 1})
    assert not spy[-1].get("retry_post"), "indexing is not idempotent: a retried POST can duplicate"


@responses.activate
def test_water_hunt_trigger_search_retries_posts(spy):
    responses.add(responses.POST, f"{ES}/idx/_search", json={"hits": {"hits": []}})
    water_hunt_trigger._es_search(ES, "k", "idx", {"query": {"match_all": {}}})
    assert spy[-1].get("retry_post") is True


@responses.activate
def test_rule_efficacy_search_retries_posts(spy, tmp_path, monkeypatch):
    (tmp_path / "seen_techniques.json").write_text(json.dumps({"T1059.001": {"technique_name": "x", "tactic": "execution"}}))
    monkeypatch.setattr(rule_efficacy, "STATE_DIR", tmp_path)
    responses.add(responses.POST, f"{ES}/{rule_efficacy.ALERTS_INDEX}/_search", status=503)
    rule_efficacy.main()
    assert spy and all(k.get("retry_post") is True for k in spy)


@responses.activate
def test_generate_rule_event_query_retries_posts(spy):
    responses.add(responses.POST, f"{ES}/logs-*/_search", json={"hits": {"hits": []}})
    generate_rule.query_elasticsearch(60)
    assert spy[-1].get("retry_post") is True
