from lab.kibana_rule import build_payload

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
    assert p["immutable"] is False and p["version"] == 1


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
