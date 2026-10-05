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


# ------------------------------------------------- per-rule overrides (tmp data)

RULE_ID = "ffaa3523-eeb1-4706-aff3-d1d59b16b0d9"


def small_mapping(rules=None):
    m = {
        "tactics": {},
        "techniques": {
            "t1003.002": {
                "secplus": ["2.4"], "isc2cc": [3], "nist": ["si-4"], "cis": ["8.5"],
                "hardening": "H-tech", "ir": "IR-tech", "risk": "R-tech",
            }
        },
    }
    if rules is not None:
        m["rules"] = rules
    return m


def small_objectives():
    return {
        "secplus": {"objectives": {"2.4": "a", "4.4": "b"}},
        "isc2cc": {"domains": {"3": "x", "5": "y"}},
        "nist_800_53": {"controls": {"si-4": "a", "ac-6": "b"}},
        "cis_v8": {"safeguards": {"8.5": "a", "5.4": "b"}},
    }


def test_rule_override_replaces_tags_per_field():
    m = small_mapping({RULE_ID: {"secplus": ["4.4"], "nist": ["ac-6"]}})
    tags = tc.tag_rule(sample_rule(), m)["tags"]
    assert "cert.secplus.4.4" in tags and "cert.secplus.2.4" not in tags
    assert "nist.800-53.ac-6" in tags and "nist.800-53.si-4" not in tags
    # fields not overridden keep the technique-level value
    assert "cert.isc2cc.d3" in tags and "cis.v8.8.5" in tags


def test_rule_override_add_mode_unions_tags():
    m = small_mapping({RULE_ID: {"mode": "add", "secplus": ["4.4"], "cis": ["5.4"]}})
    tags = tc.tag_rule(sample_rule(), m)["tags"]
    assert {"cert.secplus.2.4", "cert.secplus.4.4", "cis.v8.8.5", "cis.v8.5.4"} <= set(tags)


def test_rule_override_text_wins_and_other_text_kept():
    m = small_mapping({RULE_ID: {"hardening": "H-rule"}})
    desc = tc.tag_rule(sample_rule(), m)["description"]
    assert "H-rule" in desc and "H-tech" not in desc
    assert "IR-tech" in desc and "R-tech" in desc


def test_override_only_applies_to_its_rule():
    m = small_mapping({"00000000-0000-0000-0000-000000000000": {"secplus": ["4.4"]}})
    tags = tc.tag_rule(sample_rule(), m)["tags"]
    assert "cert.secplus.4.4" not in tags and "cert.secplus.2.4" in tags


def test_override_is_idempotent_and_does_not_mutate_mapping():
    m = small_mapping({RULE_ID: {"mode": "add", "secplus": ["4.4"]}})
    before = copy.deepcopy(m)
    once = tc.tag_rule(sample_rule(), m)
    assert tc.tag_rule(once, m) == once
    assert m == before


def test_validate_mapping_rejects_unknown_rule_id():
    m = small_mapping({"11111111-1111-1111-1111-111111111111": {"secplus": ["4.4"]}})
    errs = tc.validate_mapping(m, small_objectives(), rule_ids={RULE_ID})
    assert any("11111111-1111-1111-1111-111111111111" in e and "unknown rule" in e for e in errs)


def test_validate_mapping_accepts_known_rule_id_and_checks_its_ids():
    m = small_mapping({RULE_ID: {"secplus": ["4.4"]}})
    assert tc.validate_mapping(m, small_objectives(), rule_ids={RULE_ID}) == []
    m = small_mapping({RULE_ID: {"secplus": ["9.9"], "mode": "bogus"}})
    joined = "\n".join(tc.validate_mapping(m, small_objectives(), rule_ids={RULE_ID}))
    assert "9.9" in joined and "mode" in joined


def test_validate_mapping_rejects_malformed_rules_section():
    errs = tc.validate_mapping(small_mapping({RULE_ID: "oops"}), small_objectives(), rule_ids={RULE_ID})
    assert errs


# ------------------------------------------------- main(): CLI behaviour


@pytest.fixture
def mini(tmp_path):
    """A tiny self-contained lab: one rule, small mapping and objectives."""
    rules = tmp_path / "sigma"
    rules.mkdir()
    (tmp_path / "mapping.yml").write_text(yaml.safe_dump(small_mapping()), encoding="utf-8")
    (tmp_path / "objectives.yml").write_text(yaml.safe_dump(small_objectives()), encoding="utf-8")
    (rules / "a.yml").write_text(yaml.safe_dump(sample_rule()), encoding="utf-8")
    return tmp_path


def mini_run(mini, *flags):
    return tc.main(
        [
            *flags,
            "--rules-dir", str(mini / "sigma"),
            "--mapping", str(mini / "mapping.yml"),
            "--objectives", str(mini / "objectives.yml"),
            "--coverage", str(mini / "COVERAGE.md"),
        ]
    )


def second_rule(rid="22222222-2222-2222-2222-222222222222", tags=None):
    r = sample_rule(tags)
    r["id"], r["title"] = rid, "Second rule"
    return r


def test_main_applies_per_rule_override(mini):
    m = small_mapping({RULE_ID: {"secplus": ["4.4"]}})
    (mini / "mapping.yml").write_text(yaml.safe_dump(m), encoding="utf-8")
    assert mini_run(mini, "--write") == 0
    tags = yaml.safe_load((mini / "sigma" / "a.yml").read_text(encoding="utf-8"))["tags"]
    assert "cert.secplus.4.4" in tags and "cert.secplus.2.4" not in tags
    assert mini_run(mini, "--check") == 0


def test_main_unknown_override_rule_id_exit_2(mini, capsys):
    m = small_mapping({"33333333-3333-3333-3333-333333333333": {"secplus": ["4.4"]}})
    (mini / "mapping.yml").write_text(yaml.safe_dump(m), encoding="utf-8")
    assert mini_run(mini, "--check") == 2
    assert "33333333-3333-3333-3333-333333333333" in capsys.readouterr().err


def assert_clean_error(capsys, *needles):
    err = capsys.readouterr().err.strip()
    assert err and len(err.splitlines()) == 1, err
    assert "Traceback" not in err
    for n in needles:
        assert n in err


def test_main_empty_rule_file_is_clean_error(mini, capsys):
    (mini / "sigma" / "empty.yml").write_text("", encoding="utf-8")
    assert mini_run(mini, "--check") == 2
    assert_clean_error(capsys, "empty.yml")


def test_main_non_mapping_rule_file_is_clean_error(mini, capsys):
    (mini / "sigma" / "list.yml").write_text("- 1\n- 2\n", encoding="utf-8")
    assert mini_run(mini, "--check") == 2
    assert_clean_error(capsys, "list.yml")


def test_main_invalid_yaml_rule_is_one_line(mini, capsys):
    (mini / "sigma" / "bad.yml").write_text("a: [unclosed\nb: {\n", encoding="utf-8")
    assert mini_run(mini, "--check") == 2
    assert_clean_error(capsys, "bad.yml")


def test_main_missing_note_text_is_clean_error(mini, capsys):
    m = small_mapping()
    del m["techniques"]["t1003.002"]["ir"]
    (mini / "mapping.yml").write_text(yaml.safe_dump(m), encoding="utf-8")
    assert mini_run(mini, "--check") == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and "ir" in err


def test_main_mapping_without_techniques_is_clean_error(mini, capsys):
    (mini / "mapping.yml").write_text("tactics: {}\n", encoding="utf-8")
    assert mini_run(mini, "--check") == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.strip()


@pytest.mark.parametrize("content", ["", "- a\n", "techniques: [1]\n", "techniques: {t1003.002: oops}\n"])
def test_main_bad_mapping_file_is_clean_error(mini, capsys, content):
    (mini / "mapping.yml").write_text(content, encoding="utf-8")
    assert mini_run(mini, "--check") == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.strip()
    assert "mapping" in err


def test_main_bad_objectives_file_is_clean_error(mini, capsys):
    (mini / "objectives.yml").write_text("secplus: {}\n", encoding="utf-8")
    assert mini_run(mini, "--check") == 2
    err = capsys.readouterr().err
    assert "objectives" in err and "Traceback" not in err


def test_main_missing_mapping_file_is_clean_error(mini, capsys):
    (mini / "mapping.yml").unlink()
    assert mini_run(mini, "--check") == 2
    assert_clean_error(capsys, "mapping.yml")


def test_main_malformed_tag_reports_file(mini, capsys):
    (mini / "sigma" / "mal.yml").write_text(
        yaml.safe_dump(second_rule(tags=["attack.t1003.002", "cis.v8.eight"])), encoding="utf-8"
    )
    assert mini_run(mini, "--check") == 2
    assert_clean_error(capsys, "mal.yml", "cis.v8.eight")


def test_files_option_writes_only_selected_rules(mini):
    (mini / "sigma" / "b.yml").write_text(yaml.safe_dump(second_rule()), encoding="utf-8")
    b_before = (mini / "sigma" / "b.yml").read_bytes()
    assert mini_run(mini, "--write", "--files", str(mini / "sigma" / "a.yml")) == 0
    assert (mini / "sigma" / "b.yml").read_bytes() == b_before
    a = yaml.safe_load((mini / "sigma" / "a.yml").read_text(encoding="utf-8"))
    assert "cert.secplus.2.4" in a["tags"]
    assert not (mini / "COVERAGE.md").exists()  # subset runs never touch COVERAGE.md


def test_files_option_check_looks_only_at_selected(mini):
    (mini / "sigma" / "b.yml").write_text(yaml.safe_dump(second_rule()), encoding="utf-8")
    mini_run(mini, "--write", "--files", str(mini / "sigma" / "a.yml"))
    assert mini_run(mini, "--check", "--files", str(mini / "sigma" / "a.yml")) == 0
    assert mini_run(mini, "--check", "--files", str(mini / "sigma" / "b.yml")) == 1
    assert mini_run(mini, "--check") == 1


def test_files_option_missing_path_is_clean_error(mini, capsys):
    assert mini_run(mini, "--check", "--files", str(mini / "sigma" / "nope.yml")) == 2
    assert_clean_error(capsys, "nope.yml")


def test_allow_untagged_warns_and_exits_zero(mini, capsys):
    assert mini_run(mini, "--check") == 1
    capsys.readouterr()
    assert mini_run(mini, "--check", "--allow-untagged") == 0
    err = capsys.readouterr().err
    assert "warning" in err and "a.yml" in err


def test_allow_untagged_still_fails_on_drift_in_tagged_rule(mini):
    mini_run(mini, "--write")
    p = mini / "sigma" / "a.yml"
    rule = yaml.safe_load(p.read_text(encoding="utf-8"))
    rule["tags"].remove("cis.v8.8.5")
    p.write_text(yaml.safe_dump(rule), encoding="utf-8")
    assert mini_run(mini, "--check", "--allow-untagged") == 1


def test_allow_untagged_still_fails_on_malformed_tags(mini):
    (mini / "sigma" / "mal.yml").write_text(
        yaml.safe_dump(second_rule(tags=["attack.t1003.002", "cis.v8.eight"])), encoding="utf-8"
    )
    assert mini_run(mini, "--check", "--allow-untagged") == 2


def test_allow_untagged_tolerates_untagged_unmapped_technique(mini, capsys):
    mini_run(mini, "--write")
    (mini / "sigma" / "new.yml").write_text(
        yaml.safe_dump(second_rule(tags=["attack.execution", "attack.t9999"])), encoding="utf-8"
    )
    capsys.readouterr()
    assert mini_run(mini, "--check", "--allow-untagged") == 0
    assert "new.yml" in capsys.readouterr().err
    assert mini_run(mini, "--check") == 2


def test_allow_untagged_unmapped_but_tagged_rule_still_fails(mini):
    mini_run(mini, "--write")
    (mini / "sigma" / "new.yml").write_text(
        yaml.safe_dump(second_rule(tags=["attack.t9999", "cis.v8.8.5"])), encoding="utf-8"
    )
    assert mini_run(mini, "--check", "--allow-untagged") == 2


def test_allow_untagged_only_valid_with_check(mini):
    with pytest.raises(SystemExit):
        mini_run(mini, "--write", "--allow-untagged")


def test_help_documents_new_options(capsys):
    with pytest.raises(SystemExit):
        tc.main(["--help"])
    out = " ".join(capsys.readouterr().out.split())
    for word in ("--files", "--allow-untagged", "rules:", "mode"):
        assert word in out
    assert "per-rule" in (tc.__doc__ or "")


def test_write_does_not_touch_already_correct_rule(mini):
    p = mini / "sigma" / "a.yml"
    mini_run(mini, "--write")
    # hand-formatted but semantically correct: comments and layout must survive
    p.write_bytes(b"# keep me\n" + p.read_bytes())
    snapshot = p.read_bytes()
    cov = (mini / "COVERAGE.md").read_bytes()
    assert mini_run(mini, "--write") == 0
    assert p.read_bytes() == snapshot
    assert (mini / "COVERAGE.md").read_bytes() == cov


# ------------------------------------------------- reference data accuracy


def test_cis_13_5_title_is_remote_assets(objectives):
    assert objectives["cis_v8"]["safeguards"]["13.5"] == "Manage Access Control for Remote Assets"


def test_isc2cc_outline_recorded_exactly(objectives):
    cc = objectives["isc2cc"]
    assert cc["domains"] == {
        "1": "Security Principles",
        "2": "Security Governance",
        "3": "Identity and Access Management (IAM) Concepts",
        "4": "Networking and Cloud Security Concepts",
        "5": "Security Operations and Incident Response",
    }
    assert str(cc["effective_date"]) == "2026-09-01"
    assert re.match(r"\d{4}-\d{2}-\d{2}$", str(cc["retrieved"]))
    assert sum(cc["weights"].values()) == pytest.approx(100, abs=0.2)  # official page rounds to 1 decimal


def test_every_id_referenced_in_mapping_exists_in_objectives(mapping, objectives):
    """Independent of validate_mapping: techniques, tactics and rules sections."""
    valid = {
        "secplus": set(objectives["secplus"]["objectives"]),
        "isc2cc": {int(k) for k in objectives["isc2cc"]["domains"]},
        "nist": set(objectives["nist_800_53"]["controls"]),
        "cis": set(objectives["cis_v8"]["safeguards"]),
    }
    seen = 0
    for section in ("tactics", "techniques", "rules"):
        for key, entry in (mapping.get(section) or {}).items():
            for field, ok in valid.items():
                for value in entry.get(field, []):
                    seen += 1
                    norm = int(value) if field == "isc2cc" else str(value).lower()
                    assert norm in ok, f"{section}.{key}.{field}: {value!r}"
    assert seen > 100
