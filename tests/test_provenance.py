"""W16: ONE provenance contract between sf_hunt (writer), sf_safety (gate) and
water_hunt_trigger (reader / ES query)."""
import json
import sqlite3
from datetime import datetime, timezone

import pytest

import sf_hunt
import sf_safety
import water_hunt_trigger as wht


def _base(**over):
    rec = {
        "ioc": "8.8.4.4", "ioc_type": "ipv4", "hunt_id": "abcdef12-3456",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "verdict": {"score": 90, "verdict": "malicious", "conflicts": []},
    }
    rec.update(over)
    return rec


# ── normalisation / gate: new, legacy and missing shapes ──────────────────────

def test_new_shape_cli_is_actionable():
    rec = _base(provenance={"source": "user", "trust_level": "high", "origin": "cli"})
    assert sf_safety.should_water_act_on_hunt(rec).passed


def test_legacy_top_level_shape_is_still_read():
    rec = _base(source="user", trust_level="high")
    prov = sf_safety.normalize_provenance(rec)
    assert prov["source"] == "user" and prov["trust_level"] == "high"
    assert sf_safety.should_water_act_on_hunt(rec).passed


def test_legacy_low_trust_is_respected():
    rec = _base(source="user", trust_level="low")
    assert not sf_safety.should_water_act_on_hunt(rec).passed


def test_legacy_water_source_is_refused():
    rec = _base(source="water", trust_level="high")
    assert not sf_safety.should_water_act_on_hunt(rec).passed


@pytest.mark.parametrize("prov", [None, {}, "high", 5, {"source": "user"}, {"trust_level": "high"}])
def test_missing_or_partial_provenance_fails_closed_as_low_trust(prov):
    rec = _base(provenance=prov) if prov is not None else _base()
    norm = sf_safety.normalize_provenance(rec)
    assert norm["trust_level"] in {"low", "high"} and (norm["trust_level"] == "low" or norm["source"] == "unknown")
    assert not sf_safety.should_water_act_on_hunt(rec).passed


def test_record_without_any_provenance_is_low_trust():
    norm = sf_safety.normalize_provenance(_base())
    assert norm["trust_level"] == "low" and norm["source"] == "unknown"


def test_unknown_trust_value_is_low():
    rec = _base(provenance={"source": "user", "trust_level": "super-high"})
    assert sf_safety.normalize_provenance(rec)["trust_level"] == "low"
    assert not sf_safety.should_water_act_on_hunt(rec).passed


# ── writer: the shape sf_hunt produces ────────────────────────────────────────

def test_build_provenance_cli_is_operator_high():
    p = sf_safety.build_hunt_provenance("cli", verifier_id="host1")
    assert p["source"] == "user" and p["trust_level"] == "high" and p["origin"] == "cli"
    assert p["verifier_id"] == "host1"


def test_build_provenance_web_is_low_and_never_cli():
    p = sf_safety.build_hunt_provenance("web")
    assert p["trust_level"] == "low" and p["origin"] == "web"
    assert p["source"] != "user" and p["source"] != "cli"


def test_build_provenance_unknown_origin_fails_closed():
    p = sf_safety.build_hunt_provenance("carrier-pigeon")
    assert p["trust_level"] == "low" and p["source"] not in sf_safety.ACTIONABLE_SOURCES


@pytest.fixture
def captured(monkeypatch, tmp_path):
    docs = []
    monkeypatch.setattr(sf_hunt, "elk_index_doc", lambda index, doc: docs.append((index, doc)) or True)
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(sf_hunt.MEMORY_SCHEMA)
    return conn, docs


def test_cli_hunt_document_has_provenance_dict_and_no_top_level_fields(captured):
    conn, docs = captured
    sf_hunt.memory_record_hunt(conn, "8.8.4.4", "ipv4", {"verdict": {"score": 1}}, 5)
    index, doc = docs[0]
    assert index == "sf-hunt-logs"
    assert doc["provenance"]["source"] == "user"
    assert doc["provenance"]["trust_level"] == "high"
    assert doc["provenance"]["origin"] == "cli"
    assert "source" not in doc and "trust_level" not in doc
    row = conn.execute("SELECT source, trust_level FROM hunts").fetchone()
    assert (row["source"], row["trust_level"]) == ("user", "high")


def test_web_origin_hunt_is_recorded_low_trust(captured):
    conn, docs = captured
    sf_hunt.memory_record_hunt(conn, "8.8.4.4", "ipv4", {"verdict": {"score": 99}}, 5, origin="web")
    doc = docs[0][1]
    assert doc["provenance"]["trust_level"] == "low" and doc["provenance"]["origin"] == "web"
    row = conn.execute("SELECT source, trust_level FROM hunts").fetchone()
    assert row["trust_level"] == "low" and row["source"] != "user"


def test_written_cli_document_round_trips_through_the_gate(captured):
    conn, docs = captured
    result = {"verdict": {"score": 90, "verdict": "malicious", "conflicts": []}}
    sf_hunt.memory_record_hunt(conn, "8.8.4.4", "ipv4", result, 5)
    doc = docs[0][1]
    rec = dict(ioc=doc["ioc"], ioc_type=doc["ioc_type"], hunt_id=doc["hunt_id"],
               timestamp_utc=doc["@timestamp"], verdict=result["verdict"],
               provenance=doc["provenance"])
    assert sf_safety.should_water_act_on_hunt(rec).passed


def test_written_web_document_cannot_trigger_rule_generation(captured):
    conn, docs = captured
    result = {"verdict": {"score": 99, "verdict": "malicious", "conflicts": []}}
    sf_hunt.memory_record_hunt(conn, "8.8.4.4", "ipv4", result, 5, origin="web")
    doc = docs[0][1]
    rec = dict(ioc=doc["ioc"], ioc_type=doc["ioc_type"], hunt_id=doc["hunt_id"],
               timestamp_utc=doc["@timestamp"], verdict=result["verdict"],
               provenance=doc["provenance"])
    res = sf_safety.water_should_generate_rule_from_verdict(rec)
    assert not res.passed


# ── reader: ES query excludes the engine's own records ────────────────────────

def _capture_query(monkeypatch):
    seen = {}

    def fake(es_url, api_key, index, query):
        seen["query"] = query
        return {}

    monkeypatch.setattr(wht, "_es_search", fake)
    wht.fetch_recent_hunt_verdicts("https://es.example.invalid:9200", "k")
    return seen["query"]


def test_query_excludes_water_records_new_and_legacy_shape(monkeypatch):
    q = _capture_query(monkeypatch)
    must_not = json.dumps(q["query"]["bool"]["must_not"])
    assert '"provenance.source.keyword": "water"' in must_not
    assert '"source.keyword": "water"' in must_not


def test_query_uses_keyword_subfield_because_repo_creates_no_mapping():
    # sf-hunt-logs is created implicitly by the first _doc POST (dynamic mapping):
    # strings become `text` with a `.keyword` subfield, and a term query on the
    # analysed text field would not match the exact value.
    import pathlib
    root = pathlib.Path(wht.__file__).resolve().parent
    text = "".join(p.read_text(encoding="utf-8", errors="ignore")
                   for p in root.glob("*.py") if p.name != "water_hunt_trigger.py")
    assert "put_mapping" not in text and "_index_template" not in text and '"mappings"' not in text


def test_pass_end_to_end_web_record_never_generates(monkeypatch, tmp_path):
    monkeypatch.setenv("ELASTIC_URL", "https://es.example.invalid:9200")
    monkeypatch.setattr(wht, "HUNT_TRIGGERED_RULES_DIR", tmp_path / "ht")

    class Lim:
        daily_limit = 5
        def remaining(self): return 5
        def can_consume(self): return True
        def consume(self, n=1): return True
        def release(self, n=1): pass

    monkeypatch.setattr(wht, "RateLimiter", lambda *a, **k: Lim())
    base = {"ioc": "8.8.4.4", "ioc_type": "ipv4", "hunt_id": "abcdef12-3456",
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "result": {"verdict": {"score": 90, "verdict": "malicious", "conflicts": []},
                       "observed": {"event_count": 5, "honeypots": [{"name": "Cowrie", "count": 5}]},
                       "identity": {}}}
    cases = {
        "web": dict(base, provenance=sf_safety.build_hunt_provenance("web")),
        "missing": dict(base),
        "cli": dict(base, provenance=sf_safety.build_hunt_provenance("cli")),
    }
    gen_calls = []
    for name, rec in cases.items():
        monkeypatch.setattr(wht, "fetch_recent_hunt_verdicts", lambda *a, **k: [rec])
        n = wht.process_hunt_triggered_verdicts(
            lambda i, a: gen_calls.append(name) or ("title: x", "rid"), lambda *a: None, [])
        assert n == (1 if name == "cli" else 0), name
    assert gen_calls == ["cli"]
