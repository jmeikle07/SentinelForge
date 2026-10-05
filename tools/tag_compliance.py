#!/usr/bin/env python3
"""SentinelForge compliance tagger.

Author: Jahsean Meikle

Adds Security+ SY0-701, ISC2 CC, NIST SP 800-53 and CIS Controls v8 tags to
Sigma rules from docs/compliance/mapping.yml, appends a "Defender notes" block
(hardening control, IR step, risk treatment) to each description, and
regenerates docs/compliance/COVERAGE.md.

    python tools/tag_compliance.py --check   # exit 1 on drift, 2 on errors
    python tools/tag_compliance.py --write   # rewrite rules + COVERAGE.md

Tag formats:
    attack.*                       (kept as-is)
    cert.secplus.<domain>.<obj>    e.g. cert.secplus.2.4
    cert.isc2cc.d<1-5>             e.g. cert.isc2cc.d5
    nist.800-53.<control>          e.g. nist.800-53.si-4
    cis.v8.<safeguard>             e.g. cis.v8.8.5
"""
from __future__ import annotations

import argparse
import copy
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES = ROOT / "detections" / "sigma"
DEFAULT_MAPPING = ROOT / "docs" / "compliance" / "mapping.yml"
DEFAULT_OBJECTIVES = ROOT / "docs" / "compliance" / "objectives.yml"
DEFAULT_COVERAGE = ROOT / "docs" / "compliance" / "COVERAGE.md"

NOTES_MARKER = "Defender notes:"

TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
}

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
ATTACK_OTHER_RE = re.compile(r"^attack\.[gs]\d{4}$")
MANAGED = {
    "cert.secplus.": re.compile(r"^cert\.secplus\.[1-5]\.\d+$"),
    "cert.isc2cc.": re.compile(r"^cert\.isc2cc\.d[1-5]$"),
    "nist.800-53.": re.compile(r"^nist\.800-53\.[a-z]{2}-\d+(?:\.\d+)?$"),
    "cis.v8.": re.compile(r"^cis\.v8\.\d+\.\d+$"),
}


class TaggerError(Exception):
    """Base class for tagger errors."""


class UnmappedTechniqueError(TaggerError):
    """A rule uses an ATT&CK technique absent from mapping.yml (or has none)."""


class MalformedTagError(TaggerError):
    """A tag does not match an accepted format."""


def _num_key(value: str) -> list[int]:
    return [int(p) for p in value.split(".")]


def _classify(tag: object) -> str:
    """Return 'technique', 'tactic', 'managed' or 'other'; raise if malformed."""
    if not isinstance(tag, str):
        raise MalformedTagError(f"tag {tag!r} is not a string")
    if tag.startswith("attack."):
        if TECHNIQUE_RE.match(tag):
            return "technique"
        if tag[len("attack."):] in TACTICS:
            return "tactic"
        if ATTACK_OTHER_RE.match(tag):
            return "other"
        raise MalformedTagError(f"malformed ATT&CK tag: {tag}")
    for prefix, pattern in MANAGED.items():
        if tag.startswith(prefix):
            if not pattern.match(tag):
                raise MalformedTagError(f"malformed compliance tag: {tag}")
            return "managed"
    return "other"


def _notes(entry: dict) -> str:
    return (
        f"{NOTES_MARKER}\n"
        f"- Hardening control: {entry['hardening']}\n"
        f"- IR step: {entry['ir']}\n"
        f"- Risk treatment: {entry['risk']}"
    )


def tag_rule(rule: dict, mapping: dict) -> dict:
    """Return a copy of ``rule`` with compliance tags and Defender notes applied.

    Pure and idempotent: previously generated tags/notes are discarded and
    regenerated from ``mapping``.
    """
    out = copy.deepcopy(rule)
    tags = out.get("tags")
    if not isinstance(tags, list):
        raise MalformedTagError(f"rule {out.get('title')!r}: 'tags' must be a list")

    kept, techniques, tactics = [], [], []
    for tag in tags:
        kind = _classify(tag)
        if kind == "managed":
            continue
        if tag not in kept:
            kept.append(tag)
        if kind == "technique":
            key = TECHNIQUE_RE.match(tag).group(1)
            if key not in techniques:
                techniques.append(key)
        elif kind == "tactic":
            tactics.append(tag[len("attack."):])

    if not techniques:
        raise UnmappedTechniqueError(
            f"rule {out.get('title')!r} has no attack.tNNNN technique tag"
        )
    known = mapping.get("techniques", {})
    for key in techniques:
        if key not in known:
            raise UnmappedTechniqueError(
                f"technique {key} (rule {out.get('title')!r}) is not in mapping.yml"
            )

    entries = [known[k] for k in techniques]
    entries += [mapping.get("tactics", {})[t] for t in tactics if t in mapping.get("tactics", {})]

    secplus = {str(v) for e in entries for v in e.get("secplus", [])}
    isc2 = {int(v) for e in entries for v in e.get("isc2cc", [])}
    nist = {str(v).lower() for e in entries for v in e.get("nist", [])}
    cis = {str(v) for e in entries for v in e.get("cis", [])}

    generated = (
        [f"cert.secplus.{v}" for v in sorted(secplus, key=_num_key)]
        + [f"cert.isc2cc.d{v}" for v in sorted(isc2)]
        + [f"nist.800-53.{v}" for v in sorted(nist)]
        + [f"cis.v8.{v}" for v in sorted(cis, key=_num_key)]
    )
    out["tags"] = kept + generated

    base = str(out.get("description") or "")
    idx = base.find("\n\n" + NOTES_MARKER)
    if idx >= 0:
        base = base[:idx]
    elif base.startswith(NOTES_MARKER):
        base = ""
    base = base.rstrip()
    notes = _notes(known[techniques[0]])
    out["description"] = f"{base}\n\n{notes}\n" if base else f"{notes}\n"
    return out


def validate_mapping(mapping: dict, objectives: dict) -> list[str]:
    """Return a list of problems: mapping IDs absent from objectives.yml."""
    valid = {
        "secplus": set(objectives["secplus"]["objectives"]),
        "isc2cc": {int(k) for k in objectives["isc2cc"]["domains"]},
        "nist": set(objectives["nist_800_53"]["controls"]),
        "cis": set(objectives["cis_v8"]["safeguards"]),
    }
    errors = []
    for section in ("tactics", "techniques"):
        for key, entry in mapping.get(section, {}).items():
            for field, ok in valid.items():
                for value in entry.get(field, []):
                    norm = int(value) if field == "isc2cc" else str(value)
                    if field == "nist":
                        norm = norm.lower()
                    if norm not in ok:
                        errors.append(f"{section}.{key}.{field}: unknown ID {value!r}")
            if section == "techniques":
                for field in ("hardening", "ir", "risk"):
                    if not entry.get(field):
                        errors.append(f"{section}.{key}.{field}: missing text")
    return errors


def coverage_markdown(rules: list[dict], mapping: dict) -> str:
    """Render the deterministic COVERAGE.md for ``rules``."""
    tagged = sorted(
        (tag_rule(r, mapping) for r in rules),
        key=lambda r: (str(r.get("title")), str(r.get("id"))),
    )

    def pick(tags, prefix):
        return [t[len(prefix):] for t in tags if t.startswith(prefix)]

    lines = [
        "# SentinelForge Compliance Coverage",
        "",
        "<!-- Generated by tools/tag_compliance.py --write. Do not edit by hand. -->",
        "",
        "Author: Jahsean Meikle",
        "",
        "Each detection rule is tagged with CompTIA Security+ SY0-701 objectives,",
        "ISC2 Certified in Cybersecurity (CC) domains, NIST SP 800-53 rev5 controls and",
        "CIS Controls v8 safeguards. IDs are validated against",
        "`docs/compliance/objectives.yml`.",
        "",
        f"Rules covered: **{len(tagged)}**",
        "",
        "## Rules",
        "",
        "| Rule | ID | ATT&CK | Security+ SY0-701 | ISC2 CC | NIST 800-53 | CIS v8 |",
        "|---|---|---|---|---|---|---|",
    ]
    used = {}
    for r in tagged:
        tags = r["tags"]
        techs = [m.group(1).upper() for t in tags if (m := TECHNIQUE_RE.match(t))]
        for t in techs:
            used[t.lower()] = True
        row = [
            str(r["title"]).replace("|", "/"),
            f"`{r['id']}`",
            ", ".join(techs),
            ", ".join(pick(tags, "cert.secplus.")),
            ", ".join(d.upper() for d in pick(tags, "cert.isc2cc.")),
            ", ".join(c.upper() for c in pick(tags, "nist.800-53.")),
            ", ".join(pick(tags, "cis.v8.")),
        ]
        lines.append("| " + " | ".join(row) + " |")

    lines += [
        "",
        "## Defender notes by technique",
        "",
        "| Technique | Hardening control | IR step | Risk treatment |",
        "|---|---|---|---|",
    ]
    for key in sorted(used, key=lambda k: _num_key(k[1:])):
        e = mapping["techniques"][key]
        cells = [e["hardening"], e["ir"], e["risk"]]
        lines.append(
            f"| {key.upper()} | " + " | ".join(c.replace("|", "/") for c in cells) + " |"
        )
    return "\n".join(lines) + "\n"


class _Dumper(yaml.SafeDumper):
    pass


def _str_representer(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper.add_representer(str, _str_representer)


def dump_rule(rule: dict) -> str:
    text = yaml.dump(
        rule, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=4096,
        default_flow_style=False,
    )
    if yaml.safe_load(text) != rule:  # never write something that changes meaning
        raise TaggerError(f"round-trip mismatch for rule {rule.get('title')!r}")
    return text


def _read_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SentinelForge compliance tagger")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 if rules/COVERAGE.md drift")
    mode.add_argument("--write", action="store_true", help="rewrite tags, notes and COVERAGE.md")
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING)
    parser.add_argument("--objectives", type=Path, default=DEFAULT_OBJECTIVES)
    parser.add_argument("--coverage", type=Path, default=DEFAULT_COVERAGE)
    args = parser.parse_args(argv)

    mapping = _read_yaml(args.mapping)
    objectives = _read_yaml(args.objectives)
    problems = validate_mapping(mapping, objectives)
    if problems:
        for p in problems:
            print(f"mapping error: {p}", file=sys.stderr)
        return 2

    paths = sorted(args.rules_dir.glob("*.yml"))
    originals, tagged = [], []
    for path in paths:
        try:
            rule = _read_yaml(path)
            new = tag_rule(rule, mapping)
        except TaggerError as exc:
            print(f"{path.name}: {exc}", file=sys.stderr)
            return 2
        except yaml.YAMLError as exc:
            print(f"{path.name}: invalid YAML: {exc}", file=sys.stderr)
            return 2
        originals.append(rule)
        tagged.append(new)

    coverage = coverage_markdown(originals, mapping)
    drift = [p.name for p, o, n in zip(paths, originals, tagged) if o != n]
    cov_current = args.coverage.read_text(encoding="utf-8") if args.coverage.exists() else None
    cov_drift = cov_current != coverage

    if args.check:
        for name in drift:
            print(f"drift: {name} needs --write", file=sys.stderr)
        if cov_drift:
            print(f"drift: {args.coverage} is out of date", file=sys.stderr)
        return 1 if drift or cov_drift else 0

    for path, old, new in zip(paths, originals, tagged):
        if old != new:
            path.write_bytes(dump_rule(new).encode("utf-8"))
    if cov_drift:
        args.coverage.parent.mkdir(parents=True, exist_ok=True)
        args.coverage.write_bytes(coverage.encode("utf-8"))
    print(f"tagged {len(drift)} rule(s); coverage {'updated' if cov_drift else 'unchanged'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
