"""README tables are generated from rules + mapping, never hand-typed.

The generator is tested against small tmp fixtures. Exactly one test
(test_live_readme_block_is_current) touches live repo data.
"""
from pathlib import Path

import pytest
import yaml

from lab.coverage import TACTICS
from tools import readme_tables as rt

ROOT = Path(__file__).resolve().parent.parent


def rule(title, tags, rid="00000000-0000-0000-0000-000000000001"):
    return {"title": title, "id": rid, "tags": tags}


MAPPING = {
    "techniques": {
        "t1059.001": {"hardening": "H1", "ir": "I1", "risk": "R1"},
        "t1003.002": {"hardening": "H2", "ir": "I2", "risk": "R2"},
        "t1486": {"hardening": "H3", "ir": "I3", "risk": "R3"},
        "t1595": {"hardening": "H4 | pipe", "ir": "I4", "risk": "R4"},
    }
}

OBJECTIVES = {
    "secplus": {"objectives": {"2.4": "Indicators", "4.4": "Monitoring"}},
    "isc2cc": {"domains": {"3": "IAM", "5": "SecOps"}},
}

RULES = [
    rule("a", ["attack.execution", "attack.t1059.001", "cert.secplus.2.4", "cert.isc2cc.d5"]),
    rule("b", ["attack.credential_access", "attack.t1003.002", "cert.secplus.2.4",
               "cert.secplus.4.4", "cert.isc2cc.d3"]),
    rule("c", ["attack.execution", "attack.t1059.001"]),
]

README = (
    "intro\n"
    f"{rt.BEGIN}\nold\n{rt.END}\n"
    "middle\n"
    f"{rt.CERT_BEGIN}\nold\n{rt.CERT_END}\n"
    "outro\n"
)


# ---------------------------------------------------------------- tactic order


def test_tactic_order_covers_all_14_tactics_in_kill_chain_order():
    assert len(rt.TACTIC_ORDER) == 14
    assert rt.TACTIC_ORDER == [t.replace("-", "_") for t in TACTICS]
    assert rt.TACTIC_ORDER[0] == "reconnaissance" and rt.TACTIC_ORDER[-1] == "impact"
    assert rt.TACTIC_ORDER.index("resource_development") < rt.TACTIC_ORDER.index("initial_access")


def test_impact_and_recon_rules_are_counted_and_rendered():
    rules = [rule("r", ["attack.reconnaissance", "attack.t1595"]),
             rule("i", ["attack.impact", "attack.t1486"])]
    assert rt.summary(rules)["tactics"] == 2
    rows = rt.detections_table(rules, MAPPING).splitlines()[2:]
    assert rows[0].startswith("| Reconnaissance | T1595 |")
    assert rows[1].startswith("| Impact | T1486 |")


# ---------------------------------------------------------------- summary/table


def test_summary_counts_come_from_the_rules():
    s = rt.summary(RULES)
    assert s == {"rules": 3, "techniques": 2, "tactics": 2}


def test_table_has_one_row_per_technique_with_counts_and_defender_notes():
    lines = rt.detections_table(RULES, MAPPING).splitlines()
    assert lines[0] == "| Tactic | Technique | Rules | Hardening | Incident response | Risk |"
    rows = lines[2:]
    assert rows == [
        "| Execution | T1059.001 | 2 | H1 | I1 | R1 |",
        "| Credential Access | T1003.002 | 1 | H2 | I2 | R2 |",
    ]


def test_table_escapes_pipes_in_cells():
    t = rt.detections_table([rule("r", ["attack.reconnaissance", "attack.t1595"])], MAPPING)
    assert "H4 / pipe" in t


def test_rows_sorted_by_tactic_then_technique_number():
    rules = [
        rule("x", ["attack.credential_access", "attack.t1003.002"]),
        rule("y", ["attack.execution", "attack.t1059.001"]),
        rule("z", ["attack.impact", "attack.t1486"]),
    ]
    order = [ln.split("|")[2].strip() for ln in rt.detections_table(rules, MAPPING).splitlines()[2:]]
    assert order == ["T1059.001", "T1003.002", "T1486"]


def test_primary_tactic_is_earliest_in_kill_chain():
    r = rule("m", ["attack.impact", "attack.execution", "attack.t1059.001"])
    assert rt.detections_table([r], MAPPING).splitlines()[2].startswith("| Execution |")


# ---------------------------------------------------------------- errors


def test_unmapped_technique_raises_clear_error_not_keyerror():
    r = rule("x", ["attack.execution", "attack.t9999"])
    with pytest.raises(rt.TableError, match="t9999"):
        rt.detections_table([r], MAPPING)


def test_rule_without_tactic_raises_clear_error():
    with pytest.raises(rt.TableError, match="no ATT&CK tactic"):
        rt.detections_table([rule("notactic", ["attack.t1059.001"])], MAPPING)


def test_mapping_entry_missing_text_raises_clear_error():
    bad = {"techniques": {"t1059.001": {"hardening": "H"}}}
    with pytest.raises(rt.TableError, match="ir"):
        rt.detections_table([RULES[0]], bad)


def test_rule_with_bad_tags_raises_clear_error():
    with pytest.raises(rt.TableError):
        rt.summary([{"title": "x", "tags": "attack.t1059"}])


def test_cert_table_unknown_objective_raises_clear_error():
    r = rule("x", ["cert.secplus.9.9"])
    with pytest.raises(rt.TableError, match="9.9"):
        rt.cert_table([r], OBJECTIVES)


# ---------------------------------------------------------------- cert table


def test_cert_table_counts_rules_per_objective_and_domain():
    table = rt.cert_table(RULES, OBJECTIVES)
    assert "| 2.4 | Indicators | 2 |" in table
    assert "| 4.4 | Monitoring | 1 |" in table
    assert "| D3 | IAM | 1 |" in table
    assert "| D5 | SecOps | 1 |" in table
    assert "| 1.1 |" not in table  # objectives with zero rules are not listed


# ---------------------------------------------------------------- render/main


def test_render_readme_replaces_only_the_marked_blocks():
    out = rt.render_readme(README, RULES, MAPPING, OBJECTIVES)
    assert out.startswith("intro\n") and out.endswith("outro\n")
    assert "\nmiddle\n" in out and "old" not in out
    assert "3 Sigma rules covering 2 ATT&CK techniques" in out
    assert rt.render_readme(out, RULES, MAPPING, OBJECTIVES) == out  # idempotent


def test_render_readme_missing_markers_is_clear_error():
    with pytest.raises(rt.TableError, match="markers"):
        rt.render_readme("no markers", RULES, MAPPING, OBJECTIVES)


@pytest.fixture
def lab(tmp_path):
    rules = tmp_path / "sigma"
    rules.mkdir()
    for i, r in enumerate(RULES):
        (rules / f"r{i}.yml").write_text(yaml.safe_dump(r), encoding="utf-8")
    (tmp_path / "mapping.yml").write_text(yaml.safe_dump(MAPPING), encoding="utf-8")
    (tmp_path / "objectives.yml").write_text(yaml.safe_dump(OBJECTIVES), encoding="utf-8")
    (tmp_path / "README.md").write_text(README, encoding="utf-8")
    return tmp_path


def run(lab, *flags):
    return rt.main([
        *flags,
        "--rules-dir", str(lab / "sigma"),
        "--mapping", str(lab / "mapping.yml"),
        "--objectives", str(lab / "objectives.yml"),
        "--readme", str(lab / "README.md"),
    ])


def test_main_check_write_check_cycle(lab):
    assert run(lab, "--check") == 1
    assert run(lab, "--write") == 0
    assert run(lab, "--check") == 0
    snapshot = (lab / "README.md").read_bytes()
    assert run(lab, "--write") == 0
    assert (lab / "README.md").read_bytes() == snapshot


def test_main_unmapped_technique_exits_2_with_one_line(lab, capsys):
    (lab / "sigma" / "bad.yml").write_text(
        yaml.safe_dump(rule("bad", ["attack.execution", "attack.t9999"])), encoding="utf-8")
    assert run(lab, "--check") == 2
    err = capsys.readouterr().err.strip()
    assert len(err.splitlines()) == 1 and "t9999" in err and "Traceback" not in err


def test_main_rule_without_tactic_exits_2(lab, capsys):
    (lab / "sigma" / "bad.yml").write_text(
        yaml.safe_dump(rule("bad", ["attack.t1059.001"])), encoding="utf-8")
    assert run(lab, "--write") == 2
    assert "no ATT&CK tactic" in capsys.readouterr().err


def test_main_invalid_yaml_exits_2(lab, capsys):
    (lab / "sigma" / "bad.yml").write_text("a: [oops\n", encoding="utf-8")
    assert run(lab, "--check") == 2
    err = capsys.readouterr().err.strip()
    assert len(err.splitlines()) == 1 and "bad.yml" in err


# ---------------------------------------------------------------- live data (the one coupling)


def test_live_readme_block_is_current():
    """If this fails: python tools/readme_tables.py --write"""
    assert rt.main(["--check"]) == 0
