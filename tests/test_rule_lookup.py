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


# ── W19 / W20 ────────────────────────────────────────────────────────────────

def _rule(tag, title="r", status="experimental", rid="1"):
    return f"title: {title}\nid: {rid}\nstatus: {status}\nlevel: low\ntags:\n  - attack.{tag}\n"


def test_broken_yaml_with_recoverable_tags_is_not_counted_as_coverage(sigma, caplog):
    # valid-looking header/tags, but the document as a whole does not parse
    (sigma / "bad.yml").write_text(
        "title: broken\nid: 7\nstatus: test\ntags:\n  - attack.t1046\ndetection: [unclosed\n  x: : :\n",
        encoding="utf-8")
    with caplog.at_level("WARNING"):
        rules = hwr.find_rules_for_techniques(["T1046"])
    assert "bad.yml" not in {r["filename"] for r in rules}
    msgs = [r.getMessage() for r in caplog.records if "bad.yml" in r.getMessage()]
    assert msgs and "skip" in msgs[0].lower()


def test_broken_hunt_triggered_file_is_skipped_too(sigma):
    (sigma / "hunt-triggered" / "bad.yml").write_text("title: [x\ntags:\n  - attack.t1046\n  y: : :\n", encoding="utf-8")
    assert "bad.yml" not in {r["filename"] for r in hwr.find_rules_for_techniques(["T1046"])}


def test_load_active_rules_raises_for_broken_file(sigma):
    (sigma / "bad.yml").write_text("title: [x\n  y: : :\n", encoding="utf-8")
    with pytest.raises(hwr.RuleLoadError, match="bad.yml"):
        hwr.load_active_rules()


def _names(rules):
    return sorted(r["filename"] for r in rules)


def test_subtechnique_query_does_not_match_sibling_subtechnique(sigma):
    (sigma / "a.yml").write_text(_rule("t1110.001"), encoding="utf-8")
    (sigma / "b.yml").write_text(_rule("t1110.003"), encoding="utf-8")
    assert _names(hwr.find_rules_for_techniques(["T1110.001"])) == ["a.yml"]


def test_subtechnique_query_still_matches_parent_tagged_rule(sigma):
    (sigma / "p.yml").write_text(_rule("t1110"), encoding="utf-8")
    (sigma / "b.yml").write_text(_rule("t1110.003"), encoding="utf-8")
    assert _names(hwr.find_rules_for_techniques(["T1110.001"])) == ["p.yml"]


def test_parent_query_matches_every_subtechnique_rule(sigma):
    (sigma / "a.yml").write_text(_rule("t1110.001"), encoding="utf-8")
    (sigma / "b.yml").write_text(_rule("t1110.003"), encoding="utf-8")
    (sigma / "p.yml").write_text(_rule("t1110"), encoding="utf-8")
    (sigma / "other.yml").write_text(_rule("t1111"), encoding="utf-8")
    assert _names(hwr.find_rules_for_techniques(["T1110"])) == ["a.yml", "b.yml", "p.yml"]


def test_technique_ids_in_query_are_case_insensitive(sigma):
    (sigma / "a.yml").write_text(_rule("t1110.001"), encoding="utf-8")
    assert _names(hwr.find_rules_for_techniques(["t1110.001"])) == ["a.yml"]


def test_deprecated_rules_are_not_coverage(sigma):
    (sigma / "old.yml").write_text(_rule("t1110.001", status="deprecated"), encoding="utf-8")
    assert hwr.find_rules_for_techniques(["T1110.001"]) == []
    assert all(r.get("status") != "deprecated" for r in hwr.load_active_rules())


def test_production_and_hunt_dirs_share_one_parse_cache(sigma, monkeypatch):
    calls = []
    real = yaml.safe_load
    monkeypatch.setattr(hwr.yaml, "safe_load", lambda t: calls.append(1) or real(t))
    hwr.find_rules_for_techniques(["T1046"])
    n = len(calls)
    hwr.load_active_rules()  # same files, same (mtime, size): no re-parse
    assert len(calls) == n


def test_yaml_extension_is_scanned_like_lab_coverage(sigma):
    (sigma / "x.yaml").write_text(_rule("t1046", title="yaml-ext"), encoding="utf-8")
    assert "x.yaml" in {r["filename"] for r in hwr.find_rules_for_techniques(["T1046"])}


def test_module_has_no_dead_technique_ids_or_duplicated_glob_loops():
    import inspect
    src = inspect.getsource(hwr)
    assert "technique_ids = sorted" not in src
    assert src.count(".glob(") <= 2
