import pytest

from lab.kibana_rule import build_payload, build_update_payload, technique_tags

RULE = {"title": "T", "id": "ae4b60ce-b6c0-4ca8-82df-9469de001220", "level": "high",
        "description": "d", "tags": ["attack.t1059.001", "cert.isc2cc.d2"],
        "references": ["http://r"], "falsepositives": ["admin"]}


def test_payload_lookback_covers_interval_plus_buffer():
    p = build_payload(RULE, ["q"], "A B")
    assert p["interval"] == "5m"
    assert p["from"] == "now-6m"


def test_payload_indices_have_no_duplicates():
    idx = build_payload(RULE, ["q"], "A")["index"]
    assert len(idx) == len(set(idx))
    assert ".ds-logs-*" not in idx and "endgame-*" not in idx
    assert {"logs-*", "winlogbeat-*", "filebeat-*"} <= set(idx)


def test_payload_shape_preserved():
    p = build_payload(RULE, ["q"], "Jahsean Meikle")
    assert p["type"] == "query" and p["language"] == "lucene"
    assert p["query"] == "q"
    assert p["name"] == "T" and p["description"] == "d"
    assert p["severity"] == "high" and p["risk_score"] == 73
    assert p["enabled"] is True and p["max_signals"] == 100
    assert p["tags"] == ["attack.t1059.001", "cert.isc2cc.d2"]
    assert p["references"] == ["http://r"]
    assert p["author"] == ["Jahsean Meikle"]
    assert p["rule_id"] == RULE["id"]
    assert p["false_positives"] == ["admin"]
    assert "immutable" not in p and "version" not in p


def test_severity_and_risk_mapping():
    for level, sev, risk in [("critical", "critical", 99), ("high", "high", 73),
                             ("medium", "medium", 47), ("low", "low", 21),
                             ("informational", "low", 21)]:
        p = build_payload({**RULE, "level": level}, ["q"], "a")
        assert (p["severity"], p["risk_score"]) == (sev, risk)
    p = build_payload({k: v for k, v in RULE.items() if k != "level"}, ["q"], "a")
    assert (p["severity"], p["risk_score"]) == ("medium", 47)


def test_defaults_for_missing_fields():
    p = build_payload({"id": "x"}, ["q"], "a")
    assert p["name"] == "Unnamed Rule"
    assert p["description"] == "No description provided."
    assert p["tags"] == [] and p["references"] == [] and p["false_positives"] == []


def test_multiple_queries_are_ored():
    assert build_payload(RULE, ["a:1", "b:2"], "a")["query"] == "(a:1) OR (b:2)"


def test_empty_queries_rejected():
    import pytest
    with pytest.raises(ValueError):
        build_payload(RULE, [], "a")


def test_level_is_case_insensitive():
    for level, sev in [("HIGH", "high"), ("Critical", "critical"), (" Medium ", "medium")]:
        assert build_payload({**RULE, "level": level}, ["q"], "a")["severity"] == sev


def test_falsepositives_string_becomes_list():
    assert build_payload({**RULE, "falsepositives": "admins"}, ["q"], "a")["false_positives"] == ["admins"]
    assert build_payload({**RULE, "falsepositives": None}, ["q"], "a")["false_positives"] == []


def test_null_tags_and_references_become_empty_lists():
    p = build_payload({**RULE, "tags": None, "references": None}, ["q"], "a")
    assert p["tags"] == [] and p["references"] == []


@pytest.mark.parametrize("rid", [None, "", "  "])
def test_missing_id_rejected(rid):
    with pytest.raises(ValueError, match="id"):
        build_payload({**RULE, "id": rid}, ["q"], "a")


def test_update_payload_contains_only_engine_owned_fields():
    full = build_payload(RULE, ["q"], "A")
    full.update({"exceptions_list": [1], "actions": [2], "note": "n", "id": "uuid", "foo": 1})
    upd = build_update_payload(full)
    assert upd["rule_id"] == RULE["id"]
    assert set(upd) == {"rule_id", "name", "description", "query", "language", "severity", "risk_score",
                        "tags", "references", "author", "false_positives", "index", "from",
                        "interval", "max_signals", "type"}


def test_technique_tags_extracts_attack_techniques_lowercased():
    assert technique_tags(["attack.execution", "attack.T1059.001", "cert.x", None, "attack.t1003"]) == \
        {"attack.t1059.001", "attack.t1003"}
