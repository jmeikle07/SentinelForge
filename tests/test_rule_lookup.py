import pytest
import yaml

import hunt_water_rules as hwr

RULE = """title: {title}
id: {id}
status: test
level: low
tags:
  - attack.t1046
"""


@pytest.fixture
def sigma(tmp_path, monkeypatch):
    d = tmp_path / "sigma"
    (d / "hunt-triggered").mkdir(parents=True)
    for i in range(3):
        (d / f"r{i}.yml").write_text(RULE.format(title=f"r{i}", id=i), encoding="utf-8")
    (d / "hunt-triggered" / "h.yml").write_text(
        "# Triggered by hunt_id: abc\n# IOC: 203.0.113.9\n" + RULE.format(title="h", id=9), encoding="utf-8")
    monkeypatch.setattr(hwr, "SIGMA_DIR", d)
    monkeypatch.setattr(hwr, "SIGMA_HUNT_DIR", d / "hunt-triggered")
    hwr._PARSE_CACHE.clear()
    return d


def test_rule_lookup_caches_parsed_rules(sigma, monkeypatch):
    calls = []
    real = yaml.safe_load
    monkeypatch.setattr(hwr.yaml, "safe_load", lambda t: calls.append(1) or real(t))
    first = hwr.find_rules_for_techniques(["T1046"])
    n = len(calls)
    assert len(first) == 4 and n == 4
    for _ in range(3):
        hwr.find_rules_for_techniques(["T1046"])
    assert len(calls) == n  # files parsed once across repeated lookups


def test_rule_lookup_cache_invalidates_when_file_changes(sigma):
    hwr.find_rules_for_techniques(["T1046"])
    f = sigma / "r0.yml"
    f.write_text(RULE.format(title="renamed-longer-title", id=0), encoding="utf-8")
    titles = {r["title"] for r in hwr.find_rules_for_techniques(["T1046"])}
    assert "renamed-longer-title" in titles


def test_hunt_triggered_provenance_is_parsed(sigma):
    rules = hwr.find_rules_for_techniques(["T1046"])
    h = [r for r in rules if r["is_hunt_triggered"]][0]
    assert h["triggered_by_ioc"] == "203.0.113.9" and h["triggered_by_hunt_id"] == "abc"


def test_unparseable_file_is_logged_and_skipped(sigma, caplog):
    (sigma / "bad.yml").write_text("title: [unclosed\n  tags: : :\n", encoding="utf-8")
    with caplog.at_level("WARNING"):
        rules = hwr.find_rules_for_techniques(["T1046"])
    assert all(r["filename"] != "bad.yml" for r in rules)
    assert any("bad.yml" in r.message for r in caplog.records)


def test_default_dirs_anchored_to_module_location():
    from pathlib import Path
    root = Path(hwr.__file__).resolve().parent
    assert hwr.SIGMA_DIR == root / "detections" / "sigma"
    assert hwr.SIGMA_DIR.is_absolute()
