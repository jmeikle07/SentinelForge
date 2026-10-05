import json

import pytest

from lab import coverage


def _rule(tmp_path, name, body):
    (tmp_path / name).write_text(body, encoding="utf-8")


def test_tactics_are_hyphenated_enterprise_names_only(tmp_path):
    _rule(tmp_path, "a.yml", "title: a\ntags:\n- attack.g0016\n- attack.s0002\n- attack.defense_evasion\n- attack.t1036.005\n")
    cov = coverage.rule_techniques(tmp_path)
    assert cov["T1036.005"]["tactics"] == ["defense-evasion"]  # group/software tags are not tactics


def test_multi_tactic_rule_keeps_every_tactic_in_attack_order(tmp_path):
    _rule(tmp_path, "a.yml", "title: a\ntags:\n- attack.persistence\n- attack.execution\n- attack.t1053.005\n")
    assert coverage.rule_techniques(tmp_path)["T1053.005"]["tactics"] == ["execution", "persistence"]


def test_shared_technique_unions_tactics_across_rules_and_counts_rules(tmp_path):
    _rule(tmp_path, "a.yml", "title: a\ntags:\n- attack.t1218.011\n")  # no tactic tag at all
    _rule(tmp_path, "b.yml", "title: b\ntags:\n- attack.defense_evasion\n- attack.t1218.011\n")
    t = coverage.rule_techniques(tmp_path)["T1218.011"]
    assert t["tactics"] == ["defense-evasion"] and t["rules"] == 2


def test_yaml_extension_is_scanned_and_deprecated_rules_are_not_coverage(tmp_path):
    _rule(tmp_path, "a.yaml", "title: a\ntags:\n- attack.discovery\n- attack.t1082\n")
    _rule(tmp_path, "b.yml", "title: b\nstatus: deprecated\ntags:\n- attack.discovery\n- attack.t1083\n")
    assert set(coverage.rule_techniques(tmp_path)) == {"T1082"}


@pytest.mark.parametrize("body", ["- just\n- a list\n", "title: x\ntags:\n", "title: x\ntags: notalist\n"])
def test_malformed_tags_or_root_are_skipped_without_crashing(tmp_path, body):
    _rule(tmp_path, "bad.yml", body)
    _rule(tmp_path, "ok.yml", "title: ok\ntags:\n- attack.discovery\n- attack.t1082\n")
    assert set(coverage.rule_techniques(tmp_path)) == {"T1082"}


def test_unparseable_yaml_fails_loudly_instead_of_lowering_coverage(tmp_path):
    _rule(tmp_path, "broken.yml", "title: [unclosed\n")
    with pytest.raises(coverage.CoverageError, match="broken.yml"):
        coverage.rule_techniques(tmp_path)


def test_merge_uses_state_metadata_only_when_present_and_never_invents_it(tmp_path):
    _rule(tmp_path, "a.yml", "title: a\ntags:\n- attack.discovery\n- attack.t1082\n- attack.t1016\n")
    state = {"T1082": {"confidence": "high", "deployed_at": "2026-05-01T00:00:00+00:00",
                       "technique_name": "System Information Discovery", "tactic": ""},
             "T9999": {"confidence": "low"}, "T1016": "not-a-dict"}
    merged = coverage.covered(tmp_path, state)
    assert set(merged) == {"T1082", "T1016"}  # state-only T9999 is not covered by any rule
    assert merged["T1082"]["confidence"] == "high"
    assert merged["T1082"]["tactics"] == ["discovery"]  # empty state tactic must not override the rule's
    assert merged["T1016"]["confidence"] is None and merged["T1016"]["deployed_at"] is None


def test_live_rules_cover_expected_shape():
    from pathlib import Path
    cov = coverage.covered(Path(__file__).resolve().parent.parent / "detections" / "sigma", {})
    # 34 before the rule-quality review; retagging rules to what they detect
    # (and deprecating duplicates) removed techniques the rules never covered.
    assert len(cov) >= 28
    for tech in ("T1497.001", "T1595", "T1033", "T1018", "T1021.001", "T1016.001", "T1016", "T1112"):
        assert tech in cov, tech
    for gone in ("T1057", "T1087.001", "T1482", "T1216", "T1555.004", "T1046", "T1614.001", "T1564.001"):
        assert gone not in cov, f"{gone} is only claimed by rules that do not detect it"
    assert all(t["tactics"] for t in cov.values()), "every shipped technique needs a tactic tag"
