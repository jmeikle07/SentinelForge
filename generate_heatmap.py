#!/usr/bin/env python3
"""
generate_heatmap.py — Auto-generate MITRE ATT&CK Navigator layer from the shipped Sigma rules
(detections/sigma/*.yml attack.* tags). state/seen_techniques.json only supplies per-technique
confidence / deployment metadata when it has an entry.

Run: python generate_heatmap.py   (works from any directory)
Output: docs/coverage_layer.json

Coverage percentage is computed against docs/attack_enterprise_total.json
({"enterprise_techniques": N}) when that file exists. With no such data the
layer reports the technique count only; it never guesses a denominator.

Load in ATT&CK Navigator:
  https://mitre-attack.github.io/attack-navigator/
  → Open Existing Layer → Upload File → docs/coverage_layer.json
"""

import json
import logging
import re
from pathlib import Path
from datetime import datetime, timezone

import yaml

from lab import state as lab_state

log = logging.getLogger(__name__)

ROOT        = Path(__file__).resolve().parent
STATE_FILE  = ROOT / "state" / "seen_techniques.json"
OUTPUT_FILE = ROOT / "docs" / "coverage_layer.json"
TOTAL_FILE  = ROOT / "docs" / "attack_enterprise_total.json"
RULES_DIR   = ROOT / "detections" / "sigma"
_TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def rule_techniques(rules_dir: Path) -> dict:
    """{technique id -> tactic from the same rule} for every attack.tNNNN[.NNN] tag in the rules."""
    found = {}
    for path in sorted(Path(rules_dir).glob("*.yml")):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            log.error("skipping unreadable rule %s: %s", path.name, exc)
            continue
        tags = [str(t) for t in (rule or {}).get("tags", [])]
        tactic = next((t[7:] for t in tags
                       if t.startswith("attack.") and not _TECHNIQUE_TAG.match(t)), "")
        for t in tags:
            m = _TECHNIQUE_TAG.match(t)
            if m:
                found.setdefault(m.group(1).upper(), tactic)
    return found


def load_total_techniques(total_file: Path = None):
    """ATT&CK Enterprise technique count from the data file, or None when unavailable."""
    total_file = Path(total_file) if total_file else TOTAL_FILE
    try:
        total = lab_state.read(total_file, default=None)
    except (lab_state.StateCorrupt, OSError) as exc:
        log.error("cannot read ATT&CK total from %s: %s", total_file, exc)
        return None
    count = total.get("enterprise_techniques") if isinstance(total, dict) else None
    if isinstance(count, int) and count > 0:
        return count
    if total is not None:
        log.warning("%s has no positive integer 'enterprise_techniques'; omitting percentage", total_file)
    return None


def generate_layer(state_file: Path = None, output_file: Path = None, total_file: Path = None,
                   rules_dir: Path = None) -> dict:
    """Build the layer. With rules_dir, coverage is exactly the techniques the rules tag."""
    state_file = Path(state_file) if state_file else STATE_FILE
    output_file = Path(output_file) if output_file else OUTPUT_FILE
    seen = lab_state.read(state_file, default={})
    if rules_dir is not None:
        seen = {tid: {**{"tactic": tactic}, **seen.get(tid, {})}
                for tid, tactic in rule_techniques(rules_dir).items()}
    total = load_total_techniques(total_file)

    techniques = []
    for tid, meta in seen.items():
        # Color by confidence: high=green, medium=yellow, low=light blue
        confidence = meta.get("confidence", "medium").lower()
        color = {
            "high":   "#4caf50",   # green
            "medium": "#ff9800",   # orange
            "low":    "#42a5f5",   # blue
        }.get(confidence, "#ff9800")

        comment = (
            f"Deployed: {meta.get('deployed_at','')[:10]} | "
            f"Confidence: {confidence.upper()} | "
            f"Tactic: {meta.get('tactic','').title()}"
        )

        techniques.append({
            "techniqueID": tid,
            "color":       color,
            "comment":     comment,
            "enabled":     True,
            "score":       1,
            "metadata":    [],
        })

    pct = round(len(seen) / total * 100) if total else None
    pct_suffix = f" ({pct}%)" if pct is not None else ""

    layer = {
        "name":        f"SentinelForge Detection Lab — {len(seen)} Techniques Covered{pct_suffix}",
        "versions": {
            "attack":    "16",
            "navigator": "4.9",
            "layer":     "4.5",
        },
        "domain":      "enterprise-attack",
        "description": (
            f"Auto-generated from the SentinelForge autonomous rule engine. "
            f"{len(seen)} techniques covered as of "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}. "
            f"Green = HIGH confidence, Orange = MEDIUM, Blue = LOW."
        ),
        "filters": {
            "platforms": [
                "Windows", "Linux", "macOS",
                "Network", "PRE", "Containers",
                "IaaS", "SaaS", "Office Suite",
                "Identity Provider",
            ]
        },
        "sorting":       0,
        "layout": {
            "layout":          "side",
            "aggregateFunction": "average",
            "showID":          True,
            "showName":        True,
            "showAggregateScores": False,
            "countUnscored":   False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled":  False,
        "techniques":    techniques,
        "gradient": {
            "colors":   ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "HIGH confidence",   "color": "#4caf50"},
            {"label": "MEDIUM confidence", "color": "#ff9800"},
            {"label": "LOW confidence",    "color": "#42a5f5"},
        ],
        "metadata": [],
        "links":    [],
        "showTacticRowBackground": True,
        "tacticRowBackground":     "#1a1a2e",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques":       False,
    }

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    print(f"Coverage layer written to {output_file}")
    print(f"  Techniques: {len(seen)}")
    print(f"  Coverage:   {f'{pct}%' if pct is not None else 'n/a (no ATT&CK total data file)'}")
    print("  Load at:    https://mitre-attack.github.io/attack-navigator/")
    return layer


if __name__ == "__main__":
    generate_layer(rules_dir=RULES_DIR)
