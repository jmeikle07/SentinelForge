"""Characterization test: every shipped Sigma rule must parse and convert.

Uses lab.ecs (the exact pipeline that deploys rules) instead of a private copy,
so this test cannot drift from production, and does not hard-code a rule count.
"""
from pathlib import Path

import yaml

from lab.ecs import convert_path

RULES_DIR = Path(__file__).resolve().parent.parent / "detections" / "sigma"


def test_all_sigma_rules_parse_and_convert():
    files = sorted(RULES_DIR.glob("*.yml"))
    assert files, "no Sigma rules found"
    errors = {}
    for f in files:
        try:
            yaml.safe_load(f.read_text(encoding="utf-8"))
            if not convert_path(str(f)):
                errors[f.name] = "no query produced"
        except Exception as exc:  # noqa: BLE001 - collecting all failures
            errors[f.name] = f"{type(exc).__name__}: {exc}"
    assert errors == {}, f"{len(errors)} conversion errors: {errors}"


def test_every_rule_file_is_listed_by_the_coverage_loader_or_deprecated():
    """A rule must either count as coverage or be explicitly deprecated."""
    from lab import coverage

    counted = {t for t, v in coverage.rule_techniques(RULES_DIR).items() if v["rules"]}
    active_tags = set()
    for f in RULES_DIR.glob("*.yml"):
        rule = yaml.safe_load(f.read_text(encoding="utf-8"))
        if rule.get("status") == "deprecated":
            continue
        active_tags |= {t[len("attack."):].upper() for t in rule["tags"]
                        if t.startswith("attack.t") and t[8:9].isdigit()}
    assert counted == active_tags
