"""Tests for the SentinelForge compliance tagger (tools/tag_compliance.py).

Rule-driven tests run against a frozen copy of the Sigma rules in
tests/fixtures/sigma so they do not depend on detections/sigma while it is being
edited. The "live" test is skipped by default; run it with `-m live_rules`.
"""
import copy
import re
import shutil
from pathlib import Path

import pytest
import yaml

from tools import tag_compliance as tc

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "sigma"
LIVE = ROOT / "detections" / "sigma"
MAPPING_PATH = ROOT / "docs" / "compliance" / "mapping.yml"
OBJECTIVES_PATH = ROOT / "docs" / "compliance" / "objectives.yml"

TAG_RE = {
    "secplus": re.compile(r"^cert\.secplus\.[1-5]\.\d+$"),
    "isc2cc": re.compile(r"^cert\.isc2cc\.d[1-5]$"),
    "nist": re.compile(r"^nist\.800-53\.[a-z]{2}-\d+(\.\d+)?$"),
    "cis": re.compile(r"^cis\.v8\.\d+\.\d+$"),
}


@pytest.fixture(scope="module")
def mapping():
    return yaml.safe_load(MAPPING_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def objectives():
    return yaml.safe_load(OBJECTIVES_PATH.read_text(encoding="utf-8"))


def load_rules(directory):
    return [
        (p, yaml.safe_load(p.read_text(encoding="utf-8")))
        for p in sorted(directory.glob("*.yml"))
    ]


@pytest.fixture(scope="module")
def fixture_rules():
    return load_rules(FIXTURES)


def sample_rule(tags=None):
    return {
        "title": "SAM Registry Hive Dumping via Reg Save Command",
        "id": "ffaa3523-eeb1-4706-aff3-d1d59b16b0d9",
        "description": "Detects reg save against SAM.",
        "tags": tags or ["attack.credential_access", "attack.t1003.002"],
        "level": "high",
    }


# ---------------------------------------------------------------- tag_rule


def test_tag_rule_adds_cert_nist_cis_tags_for_t1003_002(mapping):
    out = tc.tag_rule(sample_rule(), mapping)
    tags = out["tags"]
    assert "attack.t1003.002" in tags and "attack.credential_access" in tags
    assert "cert.secplus.2.4" in tags
    assert "cert.isc2cc.d3" in tags
    assert "nist.800-53.si-4" in tags
    assert "cis.v8.8.5" in tags


def test_tag_rule_does_not_mutate_input(mapping):
    rule = sample_rule()
    before = copy.deepcopy(rule)
    tc.tag_rule(rule, mapping)
    assert rule == before


def test_tag_rule_is_idempotent(mapping):
    once = tc.tag_rule(sample_rule(), mapping)
    twice = tc.tag_rule(once, mapping)
    assert once == twice
    assert len(once["tags"]) == len(set(once["tags"]))
    assert once["description"].count("Defender notes") == 1


def test_tag_rule_ignores_stale_managed_tags(mapping):
    rule = sample_rule(
        ["attack.t1003.002", "cert.secplus.1.1", "nist.800-53.ac-1", "cis.v8.1.1", "cert.isc2cc.d1"]
    )
    tags = tc.tag_rule(rule, mapping)["tags"]
    assert "cert.secplus.1.1" not in tags
    assert "cis.v8.1.1" not in tags


def test_unknown_technique_raises_unmapped_technique_error(mapping):
    rule = sample_rule(["attack.execution", "attack.t9999.999"])
    with pytest.raises(tc.UnmappedTechniqueError) as exc:
        tc.tag_rule(rule, mapping)
    assert "t9999.999" in str(exc.value)


def test_rule_without_technique_raises_unmapped(mapping):
    with pytest.raises(tc.UnmappedTechniqueError):
        tc.tag_rule(sample_rule(["attack.execution"]), mapping)


@pytest.mark.parametrize(
    "bad",
    [
        "attack.tXYZ",
        "attack.t1003.2",
        "attack.not_a_tactic",
        "cert.secplus.9.9",
        "cert.secplus.2",
        "cert.isc2cc.d9",
        "nist.800-53.SI-4",
        "nist.800-53.",
        "cis.v8.eight",
        "cis.v8.8",
    ],
)
def test_malformed_tag_rejected(mapping, bad):
    rule = sample_rule(["attack.t1003.002", bad])
    with pytest.raises(tc.MalformedTagError) as exc:
        tc.tag_rule(rule, mapping)
    assert bad in str(exc.value)


def test_non_string_or_missing_tags_rejected(mapping):
    with pytest.raises(tc.MalformedTagError):
        tc.tag_rule({"title": "x", "tags": "attack.t1003.002"}, mapping)
    with pytest.raises(tc.MalformedTagError):
        tc.tag_rule({"title": "x", "tags": [1234]}, mapping)


def test_description_gains_hardening_ir_risk_section(mapping):
    desc = tc.tag_rule(sample_rule(), mapping)["description"]
    assert desc.startswith("Detects reg save against SAM.")
    assert "Defender notes" in desc
    for label in ("Hardening control:", "IR step:", "Risk treatment:"):
        assert label in desc
    assert mapping["techniques"]["t1003.002"]["hardening"] in desc


def test_description_missing_is_created(mapping):
    rule = sample_rule()
    del rule["description"]
    assert "Defender notes" in tc.tag_rule(rule, mapping)["description"]


def test_description_notes_are_replaced_not_stacked(mapping):
    rule = tc.tag_rule(sample_rule(), mapping)
    mapping2 = copy.deepcopy(mapping)
    mapping2["techniques"]["t1003.002"]["hardening"] = "NEW HARDENING TEXT"
    out = tc.tag_rule(rule, mapping2)["description"]
    assert out.count("Defender notes") == 1
    assert "NEW HARDENING TEXT" in out
    assert mapping["techniques"]["t1003.002"]["hardening"] not in out


def test_multi_technique_rule_gets_union_of_tags(mapping):
    rule = sample_rule(["attack.t1059.001", "attack.t1105"])
    tags = tc.tag_rule(rule, mapping)["tags"]
    for key in ("t1059.001", "t1105"):
        for sp in mapping["techniques"][key]["secplus"]:
            assert f"cert.secplus.{sp}" in tags


# ---------------------------------------------------------------- mapping


def test_mapping_ids_exist_in_reference_lists(mapping, objectives):
    assert tc.validate_mapping(mapping, objectives) == []


def test_validate_mapping_reports_unknown_ids(mapping, objectives):
    bad = copy.deepcopy(mapping)
    bad["techniques"]["t1003.002"]["secplus"].append("9.9")
    bad["techniques"]["t1003.002"]["isc2cc"].append(9)
    bad["techniques"]["t1003.002"]["nist"].append("zz-99")
    bad["techniques"]["t1003.002"]["cis"].append("99.9")
    errors = tc.validate_mapping(bad, objectives)
    joined = "\n".join(errors)
    for needle in ("9.9", "zz-99", "99.9"):
        assert needle in joined
    assert len(errors) >= 4


def test_objectives_record_sources_and_retrieval_date(objectives):
    for key in ("secplus", "isc2cc", "nist_800_53", "cis_v8"):
        section = objectives[key]
        assert section["source_url"].startswith("https://")
        assert re.match(r"\d{4}-\d{2}-\d{2}$", str(section["retrieved"]))
    assert len(objectives["secplus"]["objectives"]) == 28
    assert sorted(objectives["isc2cc"]["domains"]) == ["1", "2", "3", "4", "5"]


def test_every_mapping_entry_has_all_fields(mapping):
    for key, entry in mapping["techniques"].items():
        for field in ("secplus", "isc2cc", "nist", "cis", "hardening", "ir", "risk"):
            assert entry.get(field), f"{key} missing {field}"


def test_mapping_covers_every_fixture_technique(mapping, fixture_rules):
    needed = set()
    for _, rule in fixture_rules:
        for tag in rule["tags"]:
            if re.match(r"^attack\.t\d{4}(\.\d{3})?$", tag):
                needed.add(tag[len("attack."):])
    assert len(needed) >= 36
    assert needed <= set(mapping["techniques"])


def test_mapping_covers_deprecated_and_replacement_ids(mapping):
    assert "t1035" in mapping["techniques"]
    assert "t1569.002" in mapping["techniques"]


# ---------------------------------------------------------------- rules


def test_fixture_rules_present(fixture_rules):
    assert len(fixture_rules) >= 36


def test_every_fixture_rule_has_secplus_and_isc2cc_tag(mapping, fixture_rules):
    for path, rule in fixture_rules:
        tags = tc.tag_rule(rule, mapping)["tags"]
        assert any(TAG_RE["secplus"].match(t) for t in tags), path.name
        assert any(TAG_RE["isc2cc"].match(t) for t in tags), path.name
        assert any(TAG_RE["nist"].match(t) for t in tags), path.name
        assert any(TAG_RE["cis"].match(t) for t in tags), path.name


def test_tagging_preserves_rule_ids_and_detection(mapping, fixture_rules):
    for path, rule in fixture_rules:
        out = tc.tag_rule(rule, mapping)
        assert out["id"] == rule["id"], path.name
        assert out["detection"] == rule["detection"], path.name
        assert out["logsource"] == rule["logsource"], path.name


@pytest.mark.live_rules
def test_every_shipped_rule_has_at_least_one_secplus_and_one_isc2cc_tag():
    """Run after tag_compliance --write: `pytest -m live_rules`."""
    rules = load_rules(LIVE)
    assert len(rules) >= 36
    for path, rule in rules:
        tags = rule.get("tags", [])
        assert any(TAG_RE["secplus"].match(t) for t in tags), path.name
        assert any(TAG_RE["isc2cc"].match(t) for t in tags), path.name


# ---------------------------------------------------------------- coverage


def test_coverage_markdown_lists_every_rule(mapping, fixture_rules):
    rules = [r for _, r in fixture_rules]
    md = tc.coverage_markdown(rules, mapping)
    for rule in rules:
        assert rule["title"] in md
        assert rule["id"] in md
    assert "SentinelForge" in md and "Jahsean Meikle" in md
    assert "Security+" in md and "ISC2" in md


def test_coverage_markdown_is_deterministic_and_order_independent(mapping, fixture_rules):
    rules = [r for _, r in fixture_rules]
    assert tc.coverage_markdown(rules, mapping) == tc.coverage_markdown(list(reversed(rules)), mapping)


# ---------------------------------------------------------------- main


@pytest.fixture
def workdir(tmp_path):
    rules = tmp_path / "sigma"
    shutil.copytree(FIXTURES, rules)
    return tmp_path, rules, tmp_path / "COVERAGE.md"


def run(workdir, *flags):
    _, rules, cov = workdir
    return tc.main(
        [
            *flags,
            "--rules-dir", str(rules),
            "--mapping", str(MAPPING_PATH),
            "--objectives", str(OBJECTIVES_PATH),
            "--coverage", str(cov),
        ]
    )


def test_main_check_fails_on_untagged_rules(workdir):
    assert run(workdir, "--check") == 1


def test_main_write_then_check_passes_and_is_stable(workdir):
    _, rules, cov = workdir
    assert run(workdir, "--write") == 0
    assert cov.exists()
    snapshot = {p.name: p.read_bytes() for p in rules.glob("*.yml")}
    assert run(workdir, "--check") == 0
    assert run(workdir, "--write") == 0
    assert {p.name: p.read_bytes() for p in rules.glob("*.yml")} == snapshot


def test_main_write_keeps_rule_semantics(workdir, fixture_rules, mapping):
    _, rules, _ = workdir
    run(workdir, "--write")
    for path, original in fixture_rules:
        written = yaml.safe_load((rules / path.name).read_text(encoding="utf-8"))
        assert written == tc.tag_rule(original, mapping), path.name
        assert written["id"] == original["id"]


def test_main_check_detects_coverage_drift(workdir):
    _, _, cov = workdir
    run(workdir, "--write")
    cov.write_text("stale", encoding="utf-8")
    assert run(workdir, "--check") == 1


def test_main_reports_unmapped_technique_cleanly(workdir, capsys):
    _, rules, _ = workdir
    bad = rules / "zz-bad.yml"
    rule = sample_rule(["attack.t9999.999"])
    bad.write_text(yaml.safe_dump(rule), encoding="utf-8")
    assert run(workdir, "--check") == 2
    err = capsys.readouterr().err
    assert "t9999.999" in err and "zz-bad.yml" in err


def test_main_requires_a_mode(workdir):
    with pytest.raises(SystemExit):
        run(workdir)
