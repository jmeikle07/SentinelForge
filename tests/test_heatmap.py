import json
import os
import subprocess
import sys
from pathlib import Path

import generate_heatmap as gh

SEEN = {f"T{1000 + i}": {"confidence": "high", "tactic": "execution", "deployed_at": "2026-01-01T00:00:00+00:00"}
        for i in range(5)}


def _write(tmp_path, seen=SEEN, total=None):
    state = tmp_path / "seen.json"
    state.write_text(json.dumps(seen), encoding="utf-8")
    total_file = tmp_path / "attack_total.json"
    if total is not None:
        total_file.write_text(json.dumps({"enterprise_techniques": total}), encoding="utf-8")
    return state, total_file


def test_heatmap_total_techniques_not_hardcoded(tmp_path):
    state, total_file = _write(tmp_path, total=10)
    layer = gh.generate_layer(state_file=state, output_file=tmp_path / "out.json", total_file=total_file,
                              rules_dir=None)
    assert "(50%)" in layer["name"]  # 5 of 10 from the data file
    state2, total2 = _write(tmp_path, total=20)
    layer2 = gh.generate_layer(state_file=state2, output_file=tmp_path / "out.json", total_file=total2,
                               rules_dir=None)
    assert "(25%)" in layer2["name"]       # same techniques, different denominator: nothing hard-coded


def test_heatmap_without_total_data_omits_percentage_not_guesses(tmp_path):
    state, total_file = _write(tmp_path)  # no total file written
    layer = gh.generate_layer(state_file=state, output_file=tmp_path / "out.json", total_file=total_file,
                              rules_dir=None)
    assert "%" not in layer["name"] and "5 Techniques" in layer["name"]
    assert len(layer["techniques"]) == 5


def test_heatmap_missing_state_gives_empty_layer(tmp_path):
    layer = gh.generate_layer(state_file=tmp_path / "nope.json", output_file=tmp_path / "o.json",
                              total_file=tmp_path / "nope2.json", rules_dir=None)
    assert layer["techniques"] == []


def _shipped_rule_techniques():
    from lab import coverage
    return set(coverage.rule_techniques(gh.RULES_DIR))


def test_default_generate_layer_is_what_the_cli_does_rule_coverage(tmp_path):
    """The default (no rules_dir argument) must cover what the shipped rules tag, exactly like
    `python generate_heatmap.py`; state-only coverage needs an explicit rules_dir=None."""
    import inspect
    assert inspect.signature(gh.generate_layer).parameters["rules_dir"].default == gh.RULES_DIR
    layer = gh.generate_layer(output_file=tmp_path / "o.json")
    assert {t["techniqueID"] for t in layer["techniques"]} == _shipped_rule_techniques()


def test_explicit_none_is_state_only_mode(tmp_path):
    state, total_file = _write(tmp_path)
    layer = gh.generate_layer(state_file=state, output_file=tmp_path / "o.json", total_file=total_file,
                              rules_dir=None)
    assert {t["techniqueID"] for t in layer["techniques"]} == set(SEEN)


def test_heatmap_runs_from_any_cwd_via_the_real_cli_entry_point(tmp_path):
    root = Path(gh.__file__).resolve().parent
    assert gh.STATE_FILE == root / "state" / "seen_techniques.json"
    assert gh.OUTPUT_FILE == root / "docs" / "coverage_layer.json"
    out_file = tmp_path / "o.json"
    # The real script, run from another directory, exactly as a user runs it (only the output is moved).
    subprocess.run([sys.executable, str(root / "generate_heatmap.py"), "--output", str(out_file)],
                   cwd=tmp_path, capture_output=True, text=True, check=True)
    ids = {t["techniqueID"] for t in json.loads(out_file.read_text(encoding="utf-8"))["techniques"]}
    assert ids == _shipped_rule_techniques()
    # ...and it is the very same answer as calling the function with no arguments.
    in_process = gh.generate_layer(output_file=tmp_path / "p.json")
    assert ids == {t["techniqueID"] for t in in_process["techniques"]}


def test_heatmap_has_no_legacy_branding(tmp_path):
    state, total_file = _write(tmp_path)
    layer = gh.generate_layer(state_file=state, output_file=tmp_path / "o.json", total_file=total_file,
                              rules_dir=None)
    blob = json.dumps(layer).lower()
    for bad in ("1x" "lozec", "ta" "llkitchen", "ta" "ll kitchen"):
        assert bad not in blob
    assert "SentinelForge" in layer["name"]


def test_layer_from_rules_dir_uses_rule_tags_not_state(tmp_path):
    import json
    import generate_heatmap as gh

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yml").write_text(
        """title: a
tags:
- attack.discovery
- attack.t1082
- attack.t1016
""", encoding="utf-8")
    (rules / "b.yml").write_text(
        """title: b
tags:
- attack.g0016
- attack.defense_evasion
- attack.t1059.001
""", encoding="utf-8")
    state = tmp_path / "seen.json"
    state.write_text(json.dumps({"T1082": {"confidence": "high", "deployed_at": "2026-05-01T00:00:00+00:00"},
                                 "T9999": {"confidence": "low"}}), encoding="utf-8")
    layer = gh.generate_layer(state_file=state, output_file=tmp_path / "out.json",
                              total_file=tmp_path / "none.json", rules_dir=rules)
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert set(by_id) == {"T1082", "T1016", "T1059.001"}  # T9999 only in state: not covered by a rule
    assert by_id["T1082"]["color"] == "#4caf50" and "Deployed: 2026-05-01" in by_id["T1082"]["comment"]
    # no state entry: neutral colour, no empty date, no invented confidence, group tag is not a tactic
    assert by_id["T1016"]["color"] == "#9e9e9e" and "not assessed" in by_id["T1016"]["comment"]
    assert "Deployed" not in by_id["T1016"]["comment"]
    assert "Defense Evasion" in by_id["T1059.001"]["comment"] and "G0016" not in by_id["T1059.001"]["comment"].upper()
    assert "3 Techniques" in layer["name"]
