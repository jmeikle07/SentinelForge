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
if str(ROOT) not in sys.path:  # allow `python tools/readme_tables.py`
    sys.path.insert(0, str(ROOT))

from lab.coverage import TACTICS as _KILL_CHAIN  # noqa: E402  (single source of truth)

BEGIN = "<!-- BEGIN GENERATED: detections-table -->"
END = "<!-- END GENERATED: detections-table -->"
CERT_BEGIN = "<!-- BEGIN GENERATED: cert-table -->"
CERT_END = "<!-- END GENERATED: cert-table -->"

# All 14 ATT&CK enterprise tactics in kill-chain order, tag style (underscores).
TACTIC_ORDER = [t.replace("-", "_") for t in _KILL_CHAIN]


class TableError(Exception):
    """A rule or mapping cannot be rendered into the README tables."""


def _tags(rule: object) -> list[str]:
    tags = rule.get("tags") if isinstance(rule, dict) else None
    if not isinstance(tags, list):
        title = rule.get("title") if isinstance(rule, dict) else rule
        raise TableError(f"rule {title!r}: 'tags' must be a list")
    return [t for t in tags if isinstance(t, str)]


def _techniques(rule: dict) -> list[str]:
    return [t[7:] for t in _tags(rule) if t.startswith("attack.t")]


def _tactics(rule: dict) -> list[str]:
    return [t[7:] for t in _tags(rule)
            if t.startswith("attack.") and t[7:] in TACTIC_ORDER]


def _primary_tactic(rule: dict) -> str:
    tactics = _tactics(rule)
    if not tactics:
        raise TableError(f"rule {rule.get('title')!r} has no ATT&CK tactic tag")
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
        entry = (mapping.get("techniques") or {}).get(tech)
        if not isinstance(entry, dict):
            raise TableError(f"technique {tech} has no entry in mapping.yml")
        missing = [f for f in ("hardening", "ir", "risk") if not entry.get(f)]
        if missing:
            raise TableError(f"mapping.yml technique {tech} lacks {', '.join(missing)}")
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
            for tag in _tags(r):
                if tag.startswith(prefix):
                    c[tag[len(prefix):]] = c.get(tag[len(prefix):], 0) + 1
        return c

    def numkey(k):
        return [int(p) for p in k.split(".")]

    def title(section, group, key):
        try:
            return objectives[section][group][key]
        except (KeyError, TypeError):
            raise TableError(f"objectives.yml has no {section}.{group}[{key!r}]") from None

    lines = ["| Security+ SY0-701 objective | Title | Rules |", "|---|---|---|"]
    for k, n in sorted(count("cert.secplus.").items(), key=lambda kv: numkey(kv[0])):
        lines.append(f"| {k} | {title('secplus', 'objectives', k)} | {n} |")
    lines += ["", "| ISC2 CC domain | Title | Rules |", "|---|---|---|"]
    for k, n in sorted(count("cert.isc2cc.d").items()):
        lines.append(f"| D{k} | {title('isc2cc', 'domains', k)} | {n} |")
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


def _span(readme: str, begin: str, end: str) -> tuple[int, int]:
    if begin not in readme or end not in readme or readme.index(begin) > readme.index(end):
        raise TableError(f"README.md is missing the {begin} ... {end} markers")
    return readme.index(begin), readme.index(end) + len(end)


def render_readme(readme: str, rules: list[dict], mapping: dict, objectives: dict | None = None) -> str:
    start, stop = _span(readme, BEGIN, END)
    readme = readme[:start] + render_block(rules, mapping) + readme[stop:]
    if objectives is not None:
        start, stop = _span(readme, CERT_BEGIN, CERT_END)
        block = f"{CERT_BEGIN}\n{cert_table(rules, objectives)}\n{CERT_END}"
        readme = readme[:start] + block + readme[stop:]
    return readme


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise TableError(f"{path.name}: cannot read: {exc}") from None


def _load(path: Path):
    try:
        data = yaml.safe_load(_read(path))
    except yaml.YAMLError as exc:
        raise TableError(f"{path.name}: invalid YAML: {exc}") from None
    return data


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except TableError as exc:
        print(f"error: {' '.join(str(exc).split())}", file=sys.stderr)
        return 2


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--write", action="store_true")
    ap.add_argument("--rules-dir", type=Path, default=ROOT / "detections" / "sigma")
    ap.add_argument("--mapping", type=Path, default=ROOT / "docs" / "compliance" / "mapping.yml")
    ap.add_argument("--objectives", type=Path, default=ROOT / "docs" / "compliance" / "objectives.yml")
    ap.add_argument("--readme", type=Path, default=ROOT / "README.md")
    args = ap.parse_args(argv)

    rules = [_load(p) for p in sorted(args.rules_dir.glob("*.yml"))]
    mapping = _load(args.mapping)
    objectives = _load(args.objectives)
    path = args.readme
    current = _read(path)
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
