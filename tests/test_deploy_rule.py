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


RULE_ID = "11111111-2222-3333-4444-555555555555"
URL = "https://kibana.test:5601" + RULES_PATH
EXISTING = {"rule_id": RULE_ID, "tags": ["attack.execution", "attack.t1059.001"], "enabled": False,
            "exceptions_list": [{"id": "ex1"}], "actions": [{"id": "a1"}], "note": "analyst note"}


def _conflict(existing=EXISTING, get_status=200):
    responses.add(responses.POST, URL, json={"message": "exists"}, status=409)
    responses.add(responses.GET, URL, json=existing, status=get_status)


@responses.activate
def test_deploy_conflict_gets_then_patches_only_engine_owned_fields(rule_file):
    _conflict()
    responses.add(responses.PATCH, URL, json={"id": "x"}, status=200)
    deploy_rule.deploy_to_kibana(rule_file, _settings())
    methods = [c.request.method for c in responses.calls]
    assert methods == ["POST", "GET", "PATCH"]  # never a full-replace PUT
    get = responses.calls[1].request
    assert RULE_ID in get.url and "rule_id=" in get.url
    assert get.headers["Authorization"] == "ApiKey secret-key"
    patch = responses.calls[2].request
    assert patch.url == URL
    body = json.loads(patch.body)
    assert body["rule_id"] == RULE_ID
    for forbidden in ("enabled", "exceptions_list", "actions", "note", "immutable", "version", "id"):
        assert forbidden not in body
    assert set(body) <= {"rule_id", "name", "description", "query", "language", "severity",
                         "risk_score", "tags", "references", "author", "false_positives",
                         "index", "from", "interval", "max_signals", "type"}
    assert {"name", "query", "tags", "index", "from", "interval"} <= set(body)


@responses.activate
def test_deploy_conflict_with_unrelated_existing_rule_is_refused(rule_file):
    _conflict({"rule_id": RULE_ID, "tags": ["attack.t1003.001"], "name": "Other"})
    with pytest.raises(deploy_rule.DeployError, match="not the same rule"):
        deploy_rule.deploy_to_kibana(rule_file, _settings())
    assert [c.request.method for c in responses.calls] == ["POST", "GET"]


@responses.activate
def test_deploy_conflict_existing_without_technique_tag_is_refused(rule_file):
    _conflict({"rule_id": RULE_ID, "tags": []})
    with pytest.raises(deploy_rule.DeployError):
        deploy_rule.deploy_to_kibana(rule_file, _settings())
    assert len(responses.calls) == 2


@responses.activate
def test_deploy_conflict_lineage_check_is_case_insensitive(rule_file):
    _conflict({"rule_id": RULE_ID, "tags": ["attack.T1059.001"]})
    responses.add(responses.PATCH, URL, json={}, status=200)
    deploy_rule.deploy_to_kibana(rule_file, _settings())
    assert responses.calls[-1].request.method == "PATCH"


@responses.activate
def test_deploy_conflict_get_failure_raises(rule_file):
    _conflict({}, get_status=404)
    with pytest.raises(deploy_rule.DeployError):
        deploy_rule.deploy_to_kibana(rule_file, _settings())
    assert [c.request.method for c in responses.calls] == ["POST", "GET"]


@responses.activate
def test_deploy_raises_not_sys_exit(rule_file):
    responses.add(responses.POST, "https://kibana.test:5601" + RULES_PATH, json={"e": 1}, status=400)
    with pytest.raises(deploy_rule.DeployError):
        deploy_rule.deploy_to_kibana(rule_file, _settings())


@responses.activate
def test_deploy_failed_update_raises(rule_file):
    url = "https://kibana.test:5601" + RULES_PATH
    responses.add(responses.POST, url, status=409)
    responses.add(responses.GET, url, json=EXISTING)
    responses.add(responses.PATCH, url, status=400, json={})
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


# -- input validation before any HTTP ------------------------------------------

def _no_http_deploy(path, settings=None):
    with responses.RequestsMock() as rsps:  # nothing registered: any request fails the test
        with pytest.raises((deploy_rule.DeployError, deploy_rule.ConfigError)) as ei:
            deploy_rule.deploy_to_kibana(path, settings or _settings())
        assert len(rsps.calls) == 0
    return ei.value


@pytest.mark.parametrize("line", ["", "id:\n", "id: ''\n", "id: null\n"])
def test_missing_or_empty_sigma_id_raises_before_http(tmp_path, line):
    p = tmp_path / "noid.yml"
    p.write_text(RULE.replace("id: 11111111-2222-3333-4444-555555555555\n", line), encoding="utf-8")
    err = _no_http_deploy(str(p))
    assert isinstance(err, deploy_rule.DeployError) and "id" in str(err)


def test_empty_api_key_raises_config_error_before_http(rule_file):
    s = Settings(elastic_url="https://es.test:9200", kibana_url="https://kibana.test:5601",
                 verify_tls=True, elastic_api_key="")
    err = _no_http_deploy(rule_file, s)
    assert isinstance(err, deploy_rule.ConfigError) and "ELASTIC_API_KEY" in str(err)


@responses.activate
def test_all_queries_are_deployed_joined_with_or(rule_file, monkeypatch):
    monkeypatch.setattr(deploy_rule, "convert_sigma", lambda p: ["a:1", "b:2"])
    responses.add(responses.POST, URL, json={}, status=200)
    deploy_rule.deploy_to_kibana(rule_file, _settings())
    assert json.loads(responses.calls[0].request.body)["query"] == "(a:1) OR (b:2)"


@responses.activate
def test_create_payload_has_no_immutable_or_version(rule_file):
    responses.add(responses.POST, URL, json={}, status=200)
    deploy_rule.deploy_to_kibana(rule_file, _settings())
    body = json.loads(responses.calls[0].request.body)
    assert "immutable" not in body and "version" not in body
    assert body["enabled"] is True  # only creation sends it


@responses.activate
def test_tags_null_and_string_falsepositives_deploy(tmp_path, monkeypatch):
    # pySigma itself rejects these shapes, so stub conversion: this tests the payload path only
    monkeypatch.setattr(deploy_rule, "convert_sigma", lambda p: ["q"])
    p = tmp_path / "odd.yml"
    p.write_text(RULE.replace("falsepositives:\n    - admin\n", "falsepositives: just admins\n")
                 .replace("tags:\n    - attack.execution\n    - attack.t1059.001\n", "tags:\n")
                 .replace("level: medium", "level: HIGH"), encoding="utf-8")
    responses.add(responses.POST, URL, json={}, status=200)
    deploy_rule.deploy_to_kibana(str(p), _settings())
    body = json.loads(responses.calls[0].request.body)
    assert body["tags"] == [] and body["false_positives"] == ["just admins"]
    assert body["severity"] == "high"


# -- delete / retire -------------------------------------------------------------

@responses.activate
def test_delete_rule_sends_delete_with_rule_id():
    responses.add(responses.DELETE, URL, json={}, status=200)
    deploy_rule.delete_rule(RULE_ID, _settings())
    req = responses.calls[0].request
    assert req.method == "DELETE" and f"rule_id={RULE_ID}" in req.url
    assert req.headers["kbn-xsrf"] == "true" and req.headers["Authorization"] == "ApiKey secret-key"


@responses.activate
def test_delete_rule_already_gone_is_ok():
    responses.add(responses.DELETE, URL, json={}, status=404)
    deploy_rule.delete_rule(RULE_ID, _settings())


@responses.activate
def test_delete_rule_server_error_raises():
    responses.add(responses.DELETE, URL, json={}, status=500)
    with pytest.raises(deploy_rule.DeployError):
        deploy_rule.delete_rule(RULE_ID, _settings())


@pytest.mark.parametrize("bad", ["", "  ", "not-a-uuid", "*", "../x", RULE_ID + "&x=1", None])
def test_delete_rule_refuses_empty_or_non_uuid_id(bad):
    with responses.RequestsMock() as rsps:
        with pytest.raises(deploy_rule.DeployError):
            deploy_rule.delete_rule(bad, _settings())
        assert len(rsps.calls) == 0


def test_delete_rule_empty_api_key_raises_config_error():
    s = Settings(elastic_url="https://es.test:9200", kibana_url="https://kibana.test:5601",
                 verify_tls=True, elastic_api_key="")
    with pytest.raises(deploy_rule.ConfigError):
        deploy_rule.delete_rule(RULE_ID, s)


def test_main_delete_subcommand(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://es.test:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "k")
    seen = []
    monkeypatch.setattr(deploy_rule, "delete_rule", lambda rid, st, session=None: seen.append(rid))
    deploy_rule.main(["--delete", RULE_ID])
    assert seen == [RULE_ID]


def test_main_delete_bad_id_exits_nonzero(monkeypatch):
    monkeypatch.setenv("ELASTIC_URL", "https://es.test:9200")
    monkeypatch.setenv("ELASTIC_API_KEY", "k")
    with pytest.raises(SystemExit) as ei:
        deploy_rule.main(["--delete", "nope"])
    assert ei.value.code == 1
