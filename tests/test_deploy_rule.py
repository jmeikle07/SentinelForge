import json

import pytest
import responses

import deploy_rule
from lab.config import Settings

RULE = """title: Test Rule
id: 11111111-2222-3333-4444-555555555555
status: test
description: test
author: Jahsean Meikle
date: 2026/01/01
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
falsepositives:
    - admin
level: medium
"""

RULES_PATH = "/api/detection_engine/rules"


def _settings(kibana="https://kibana.test:5601"):
    return Settings(elastic_url="https://es.test:9200", kibana_url=kibana,
                    verify_tls=True, elastic_api_key="secret-key")


@pytest.fixture
def rule_file(tmp_path):
    p = tmp_path / "rule.yml"
    p.write_text(RULE, encoding="utf-8")
    return str(p)


@responses.activate
def test_deploy_uses_kibana_url_setting_not_string_replace(rule_file):
    responses.add(responses.POST, "https://kibana.test:5601" + RULES_PATH, json={"id": "x"}, status=200)
    deploy_rule.deploy_to_kibana(rule_file, _settings())
    req = responses.calls[0].request
    assert req.url == "https://kibana.test:5601" + RULES_PATH
    assert req.headers["Authorization"] == "ApiKey secret-key"
    assert req.headers["kbn-xsrf"] == "true"


@responses.activate
def test_deploy_http_kibana_url_is_respected_verbatim(rule_file):
    responses.add(responses.POST, "http://kibana.local:5601" + RULES_PATH, json={}, status=200)
    deploy_rule.deploy_to_kibana(rule_file, _settings("http://kibana.local:5601"))
    assert responses.calls[0].request.url.startswith("http://kibana.local:5601/")


@responses.activate
def test_deploy_conflict_does_put_with_rule_id_in_body(rule_file):
    url = "https://kibana.test:5601" + RULES_PATH
    responses.add(responses.POST, url, json={"message": "exists"}, status=409)
    responses.add(responses.PUT, url, json={"id": "x"}, status=200)
    deploy_rule.deploy_to_kibana(rule_file, _settings())
    put = responses.calls[1].request
    assert put.method == "PUT"
    assert put.url == url  # no ?overwrite / ?rule_id query string
    assert json.loads(put.body)["rule_id"] == "11111111-2222-3333-4444-555555555555"


@responses.activate
def test_deploy_raises_not_sys_exit(rule_file):
    responses.add(responses.POST, "https://kibana.test:5601" + RULES_PATH, json={"e": 1}, status=400)
    with pytest.raises(deploy_rule.DeployError):
        deploy_rule.deploy_to_kibana(rule_file, _settings())


@responses.activate
def test_deploy_failed_update_raises(rule_file):
    url = "https://kibana.test:5601" + RULES_PATH
    responses.add(responses.POST, url, status=409)
    responses.add(responses.PUT, url, status=400, json={})
    with pytest.raises(deploy_rule.DeployError):
        deploy_rule.deploy_to_kibana(rule_file, _settings())


def test_deploy_unconvertible_rule_raises(tmp_path):
    p = tmp_path / "bad.yml"
    p.write_text("title: x\nid: 1\n", encoding="utf-8")
    with pytest.raises(deploy_rule.DeployError):
        deploy_rule.deploy_to_kibana(str(p), _settings())


@responses.activate
def test_deploy_author_comes_from_rule_yaml(rule_file):
    responses.add(responses.POST, "https://kibana.test:5601" + RULES_PATH, json={}, status=200)
    deploy_rule.deploy_to_kibana(rule_file, _settings())
    assert json.loads(responses.calls[0].request.body)["author"] == ["Jahsean Meikle"]


@responses.activate
def test_deploy_no_hardcoded_author_default(tmp_path):
    p = tmp_path / "noauthor.yml"
    p.write_text(RULE.replace("author: Jahsean Meikle\n", ""), encoding="utf-8")
    responses.add(responses.POST, "https://kibana.test:5601" + RULES_PATH, json={}, status=200)
    deploy_rule.deploy_to_kibana(str(p), _settings())
    body = json.loads(responses.calls[0].request.body)
    assert body["author"] == []
    assert b"1x" b"LoZec" not in responses.calls[0].request.body


def test_main_exits_nonzero_on_deploy_error(rule_file, monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://es.test:9200")

    def boom(*a, **k):
        raise deploy_rule.DeployError("boom")
    monkeypatch.setattr(deploy_rule, "deploy_to_kibana", boom)
    with pytest.raises(SystemExit) as ei:
        deploy_rule.main([rule_file])
    assert ei.value.code == 1


def test_main_exits_nonzero_when_config_missing(rule_file, monkeypatch):
    monkeypatch.delenv("ELASTIC_URL", raising=False)
    with pytest.raises(SystemExit) as ei:
        deploy_rule.main([rule_file])
    assert ei.value.code == 1


def test_deploy_payload_uses_shared_builder_lookback_and_indices(rule_file):
    import responses
    from deploy_rule import deploy_to_kibana

    settings = Settings(elastic_url="https://es:9200", kibana_url="https://kb:5601", verify_tls=True, elastic_api_key="k")
    with responses.RequestsMock() as rsps:
        rsps.add(responses.POST, "https://kb:5601/api/detection_engine/rules", json={}, status=200)
        deploy_to_kibana(str(rule_file), settings)
        body = __import__("json").loads(rsps.calls[0].request.body)
    assert body["from"] == "now-6m" and body["interval"] == "5m"
    assert ".ds-logs-*" not in body["index"] and "endgame-*" not in body["index"]
