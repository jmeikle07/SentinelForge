"""README detection table is generated from the repo, never hand-typed."""
from pathlib import Path

import yaml

from tools import readme_tables as rt

ROOT = Path(__file__).resolve().parent.parent


def _rules():
    return [yaml.safe_load(p.read_text(encoding="utf-8"))
            for p in sorted((ROOT / "detections" / "sigma").glob("*.yml"))]


def _mapping():
    return yaml.safe_load((ROOT / "docs" / "compliance" / "mapping.yml").read_text(encoding="utf-8"))


def test_summary_counts_come_from_rules():
    rules = _rules()
    s = rt.summary(rules)
    assert s["rules"] == len(rules)
    techniques = {t for r in rules for t in r["tags"] if t.startswith("attack.t")}
    assert s["techniques"] == len(techniques)


def test_table_has_one_row_per_technique_with_defender_notes():
    rules, mapping = _rules(), _mapping()
    table = rt.detections_table(rules, mapping)
    techniques = {t[7:].upper() for r in rules for t in r["tags"] if t.startswith("attack.t")}
    for t in techniques:
        assert f"| {t} |" in table, t
    e = mapping["techniques"]["t1003.002"]
    assert e["hardening"] in table and e["ir"] in table and e["risk"] in table
    assert "| Tactic | Technique | Rules | Hardening | Incident response | Risk |" in table


def test_unmapped_technique_raises():
    import pytest
    rule = {"tags": ["attack.execution", "attack.t9999"], "title": "x"}
    with pytest.raises(KeyError):
        rt.detections_table([rule], {"techniques": {}})


def test_readme_block_is_up_to_date():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert rt.render_readme(readme, _rules(), _mapping(), _objectives()) == readme


def _objectives():
    return yaml.safe_load((ROOT / "docs" / "compliance" / "objectives.yml").read_text(encoding="utf-8"))


def test_cert_table_counts_rules_per_objective():
    rules, obj = _rules(), _objectives()
    table = rt.cert_table(rules, obj)
    n24 = sum("cert.secplus.2.4" in r["tags"] for r in rules)
    title = obj["secplus"]["objectives"]["2.4"]
    assert f"| 2.4 | {title} | {n24} |" in table
    nd5 = sum("cert.isc2cc.d5" in r["tags"] for r in rules)
    assert f"| D5 | {obj['isc2cc']['domains']['5']} | {nd5} |" in table
    # objectives with zero rules are not listed
    assert "| 1.1 |" not in table
