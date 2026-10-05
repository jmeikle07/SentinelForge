"""W1: API-derived strings are escaped before Rich renders them; a render failure never loses the hunt."""
import io

import pytest
from rich.console import Console

import sf_hunt

EVIL = ["Mal [/oops]", "[link=http://x]click[/link]", "[bold red]x", "[/]"]


@pytest.fixture
def cap(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(sf_hunt, "console",
                        Console(file=buf, force_terminal=False, width=250, color_system=None))
    return buf


def _ext(name):
    return {
        "otx": {"available": True, "pulse_count": 3, "top_pulses": [name, name]},
        "greynoise": {"available": True, "classification": "malicious", "name": name,
                      "noise": True, "riot": False},
        "threatfox": {"available": True, "match_count": 2, "matches": [{"malware": name}]},
        "internetdb": {"available": True, "ports": [80], "vulns": [], "tags": [name]},
        "urlhaus": {"available": True, "listed": True, "url_count": 1, "urls_online": 1,
                    "threats": [name]},
        "malwarebazaar": {"available": True, "in_corpus": True, "signature": name, "file_type": name,
                          "vendor_count": 1},
        "abuseipdb": {"available": False, "reason": name},
        "virustotal": {"available": False, "reason": name},
        "spamhaus_drop": {"available": True, "in_drop": True, "range": name, "sbl": name},
    }


@pytest.mark.parametrize("name", EVIL)
def test_render_external_prints_api_strings_literally(cap, name):
    sf_hunt.render_external(_ext(name), "8.8.8.8")          # MarkupError before the fix
    assert name in cap.getvalue()


@pytest.mark.parametrize("name", EVIL)
def test_other_renderers_escape_untrusted_text(cap, name):
    sf_hunt.render_verdict({"verdict": "malicious", "action": "BLOCK", "score": 90,
                            "conflicts": [name], "floors_applied": [name],
                            "contributions": {name: 5.0}})
    sf_hunt.render_identity({"ip": "8.8.8.8", "asn_org": name, "country": name, "city": name})
    sf_hunt.render_observed({"error": name})
    sf_hunt.render_observed({"event_count": 3, "honeypots": [{"name": name, "count": 3}]})
    sf_hunt.render_rules({"inferred_techniques": [name],
                          "matching_rules": [{"title": name, "techniques": [name], "path": name,
                                              "is_hunt_triggered": True, "triggered_by_ioc": name,
                                              "triggered_by_hunt_id": name, "level": name}]})
    sf_hunt.render_pivots([{"question": name, "distinct_count": 2, "query_hint": name,
                            "top_examples": [{"ip": name, "events": 1}]}])
    sf_hunt.render_memory([{"timestamp_utc": "2020-01-01T00:00:00+00:00", "notes": name}])
    sf_hunt.render_history_list([{"timestamp_utc": "2020-01-01T00:00:00+00:00", "ioc": name,
                                  "ioc_type": name, "notes": name}])
    assert name in cap.getvalue()


def test_malformed_markup_in_verdict_conflicts_from_a_real_source_name(cap):
    v = sf_hunt.bucket_verdict(
        {"event_count": 5},
        {"greynoise": {"available": True, "classification": "benign", "riot": True, "name": "X [/y]"}},
        "ipv4")
    sf_hunt.render_verdict(v)          # conflict text embeds the GreyNoise name
    assert "X [/y]" in cap.getvalue()


@pytest.fixture
def mem_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(sf_hunt, "MEMORY_DIR", tmp_path)
    monkeypatch.setattr(sf_hunt, "MEMORY_DB", tmp_path / "m.db")
    monkeypatch.setattr(sf_hunt, "elk_index_doc", lambda *a, **k: False)


def test_hunt_with_hostile_names_completes_and_is_recorded(cap, mem_paths, monkeypatch):
    monkeypatch.setattr(sf_hunt, "bucket_external_domain",
                        lambda conn, d: {"otx": {"available": True, "pulse_count": 9,
                                                 "top_pulses": ["Mal [/oops]"]}})
    assert sf_hunt.hunt("example.com") == 0
    conn = sf_hunt.memory_init()
    assert len(sf_hunt.memory_lookup_ioc(conn, "example.com")) == 1
    conn.close()
    assert "Mal [/oops]" in cap.getvalue()


def test_a_render_crash_does_not_lose_the_hunt(cap, mem_paths, monkeypatch):
    """The hunt is recorded before anything is rendered."""
    monkeypatch.setattr(sf_hunt, "bucket_external_domain", lambda conn, d: {})

    def crash(*a, **k):
        raise RuntimeError("render broke")

    monkeypatch.setattr(sf_hunt, "render_external", crash)
    with pytest.raises(RuntimeError):
        sf_hunt.hunt("example.com")
    conn = sf_hunt.memory_init()
    assert len(sf_hunt.memory_lookup_ioc(conn, "example.com")) == 1
    conn.close()
