"""Generate the README detection table from detections/sigma and docs/compliance/mapping.yml.

Usage:
    python tools/readme_tables.py --check    # exit 1 if README.md is stale
    python tools/readme_tables.py --write    # rewrite the generated block

The block lives between the BEGIN/END markers in README.md. Numbers are counted from the
rule files, never typed by hand.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
BEGIN = "<!-- BEGIN GENERATED: detections-table -->"
END = "<!-- END GENERATED: detections-table -->"
CERT_BEGIN = "<!-- BEGIN GENERATED: cert-table -->"
CERT_END = "<!-- END GENERATED: cert-table -->"

TACTIC_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration",
]


def _techniques(rule: dict) -> list[str]:
    return [t[7:] for t in rule.get("tags", []) if t.startswith("attack.t")]


def _tactics(rule: dict) -> list[str]:
    return [t[7:] for t in rule.get("tags", [])
            if t.startswith("attack.") and t[7:] in TACTIC_ORDER]


def _primary_tactic(rule: dict) -> str:
    tactics = _tactics(rule)
    if not tactics:
        raise KeyError(f"rule {rule.get('title')!r} has no ATT&CK tactic tag")
    return min(tactics, key=TACTIC_ORDER.index)


def summary(rules: list[dict]) -> dict:
    techniques = {t for r in rules for t in _techniques(r)}
    tactics = {t for r in rules for t in _tactics(r)}
    return {"rules": len(rules), "techniques": len(techniques), "tactics": len(tactics)}


def detections_table(rules: list[dict], mapping: dict) -> str:
    by_tech: dict[str, dict] = {}
    for r in rules:
        for t in _techniques(r):
            row = by_tech.setdefault(t, {"tactic": _primary_tactic(r), "rules": 0})
            row["rules"] += 1
    lines = [
        "| Tactic | Technique | Rules | Hardening | Incident response | Risk |",
        "|---|---|---|---|---|---|",
    ]

    def key(item):
        tech, row = item
        parts = [int(p) for p in tech[1:].split(".")]
        return (TACTIC_ORDER.index(row["tactic"]), parts)

    for tech, row in sorted(by_tech.items(), key=key):
        entry = mapping["techniques"][tech]  # KeyError on unmapped technique
        cells = [
            row["tactic"].replace("_", " ").title(),
            tech.upper(),
            str(row["rules"]),
            entry["hardening"], entry["ir"], entry["risk"],
        ]
        lines.append("| " + " | ".join(c.replace("|", "/") for c in cells) + " |")
    return "\n".join(lines)


def cert_table(rules: list[dict], objectives: dict) -> str:
    """Rules per Security+ objective and ISC2 CC domain, counted from the rule tags."""
    def count(prefix):
        c: dict[str, int] = {}
        for r in rules:
            for tag in r.get("tags", []):
                if tag.startswith(prefix):
                    c[tag[len(prefix):]] = c.get(tag[len(prefix):], 0) + 1
        return c

    def numkey(k):
        return [int(p) for p in k.split(".")]

    lines = ["| Security+ SY0-701 objective | Title | Rules |", "|---|---|---|"]
    for k, n in sorted(count("cert.secplus.").items(), key=lambda kv: numkey(kv[0])):
        lines.append(f"| {k} | {objectives['secplus']['objectives'][k]} | {n} |")
    lines += ["", "| ISC2 CC domain | Title | Rules |", "|---|---|---|"]
    for k, n in sorted(count("cert.isc2cc.d").items()):
        lines.append(f"| D{k} | {objectives['isc2cc']['domains'][k]} | {n} |")
    return "\n".join(lines)


def render_block(rules: list[dict], mapping: dict) -> str:
    s = summary(rules)
    return (
        f"{BEGIN}\n"
        f"{s['rules']} Sigma rules covering {s['techniques']} ATT&CK techniques and "
        f"sub-techniques across {s['tactics']} tactics (counted from `detections/sigma/`). "
        "Each row is one technique; the defender columns come from "
        "`docs/compliance/mapping.yml`.\n\n"
        f"{detections_table(rules, mapping)}\n"
        f"{END}"
    )


def render_readme(readme: str, rules: list[dict], mapping: dict, objectives: dict | None = None) -> str:
    start, stop = readme.index(BEGIN), readme.index(END) + len(END)
    readme = readme[:start] + render_block(rules, mapping) + readme[stop:]
    if objectives is not None:
        start, stop = readme.index(CERT_BEGIN), readme.index(CERT_END) + len(CERT_END)
        block = f"{CERT_BEGIN}\n{cert_table(rules, objectives)}\n{CERT_END}"
        readme = readme[:start] + block + readme[stop:]
    return readme


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--write", action="store_true")
    args = ap.parse_args(argv)

    rules = [yaml.safe_load(p.read_text(encoding="utf-8"))
             for p in sorted((ROOT / "detections" / "sigma").glob("*.yml"))]
    mapping = yaml.safe_load((ROOT / "docs" / "compliance" / "mapping.yml").read_text(encoding="utf-8"))
    objectives = yaml.safe_load((ROOT / "docs" / "compliance" / "objectives.yml").read_text(encoding="utf-8"))
    path = ROOT / "README.md"
    current = path.read_text(encoding="utf-8")
    new = render_readme(current, rules, mapping, objectives)
    if args.check:
        if new != current:
            print("README.md detection table is stale; run --write", file=sys.stderr)
            return 1
        return 0
    if new != current:
        path.write_bytes(new.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
