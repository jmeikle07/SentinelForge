#!/usr/bin/env python3
"""SentinelForge compliance tagger.

Author: Jahsean Meikle

Adds Security+ SY0-701, ISC2 CC, NIST SP 800-53 and CIS Controls v8 tags to
Sigma rules from docs/compliance/mapping.yml, appends a "Defender notes" block
(hardening control, IR step, risk treatment) to each description, and
regenerates docs/compliance/COVERAGE.md.

    python tools/tag_compliance.py --check   # exit 1 on drift, 2 on errors
    python tools/tag_compliance.py --write   # rewrite rules + COVERAGE.md
    python tools/tag_compliance.py --check --allow-untagged   # CI: new rules may lack tags
    python tools/tag_compliance.py --write --files detections/sigma/x.yml   # subset

Exit codes: 0 ok, 1 drift, 2 bad input (unmapped technique, malformed tag or YAML,
bad mapping.yml). Errors are one line on stderr, never a traceback.

Per-rule overrides (per-rule): mapping.yml may carry a top-level ``rules:`` section keyed by
the Sigma rule ``id`` (UUID). An entry accepts the same fields as a technique
entry (any subset of secplus/isc2cc/nist/cis/hardening/ir/risk) plus an optional
``mode``. The override wins per field over the technique-level entry. For the
tag fields, ``mode: replace`` (default) replaces the technique value for that
field, ``mode: add`` unions the override with it; hardening/ir/risk text always
replaces. An override for a rule id that does not exist in the rules directory
is a mapping error (exit 2).

--files PATH...    --write/--check only look at (and only write) these rule
                   files; COVERAGE.md is neither checked nor written.
--allow-untagged   with --check: a rule that has no cert/nist/cis tags yet is a
                   warning (exit 0). Malformed tags and drift in already-tagged
                   rules still fail. COVERAGE.md is not compared while untagged
                   rules exist.

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
MANAGED_PREFIXES = tuple(MANAGED)

_TAG_FIELDS = ("secplus", "isc2cc", "nist", "cis")
_TEXT_FIELDS = ("hardening", "ir", "risk")
_MODES = ("replace", "add")


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
    for field in _TEXT_FIELDS:
        if not entry.get(field):
            raise TaggerError(f"mapping entry is missing the {field!r} text")
    return (
        f"{NOTES_MARKER}\n"
        f"- Hardening control: {entry['hardening']}\n"
        f"- IR step: {entry['ir']}\n"
        f"- Risk treatment: {entry['risk']}"
    )


def _override_for(rule: dict, mapping: dict) -> dict:
    overrides = mapping.get("rules")
    if not isinstance(overrides, dict) or rule.get("id") is None:
        return {}
    entry = overrides.get(str(rule["id"]))
    return entry if isinstance(entry, dict) else {}


def has_compliance_tags(rule: object) -> bool:
    """True if ``rule`` carries any cert./nist./cis. tag (valid or not)."""
    tags = rule.get("tags") if isinstance(rule, dict) else None
    return isinstance(tags, list) and any(
        isinstance(t, str) and t.startswith(MANAGED_PREFIXES) for t in tags
    )


def tag_rule(rule: dict, mapping: dict) -> dict:
    """Return a copy of ``rule`` with compliance tags and Defender notes applied.

    Pure and idempotent: previously generated tags/notes are discarded and
    regenerated from ``mapping``. A per-rule override (``mapping['rules'][id]``)
    wins over the technique-level entry per field; see the module docstring.
    """
    if not isinstance(rule, dict):
        raise MalformedTagError("rule is not a YAML mapping (empty or wrong type)")
    if not isinstance(mapping, dict):
        raise TaggerError("mapping is not a YAML mapping")
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
    known = mapping.get("techniques")
    if not isinstance(known, dict):
        raise TaggerError("mapping has no 'techniques' section")
    for key in techniques:
        if key not in known:
            raise UnmappedTechniqueError(
                f"technique {key} (rule {out.get('title')!r}) is not in mapping.yml"
            )
        if not isinstance(known[key], dict):
            raise TaggerError(f"mapping technique {key} is not a mapping")

    tactic_map = mapping.get("tactics") or {}
    entries = [known[k] for k in techniques]
    entries += [tactic_map[t] for t in tactics if isinstance(tactic_map.get(t), dict)]
    override = _override_for(out, mapping)
    add = override.get("mode", "replace") == "add"

    values = {}
    for field in _TAG_FIELDS:
        base = [v for e in entries for v in e.get(field, [])]
        if field in override:
            mine = list(override[field] or [])
            base = base + mine if add else mine
        values[field] = base

    secplus = {str(v) for v in values["secplus"]}
    isc2 = {int(v) for v in values["isc2cc"]}
    nist = {str(v).lower() for v in values["nist"]}
    cis = {str(v) for v in values["cis"]}

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
    note_entry = dict(known[techniques[0]])
    note_entry.update({f: override[f] for f in _TEXT_FIELDS if override.get(f)})
    notes = _notes(note_entry)
    out["description"] = f"{base}\n\n{notes}\n" if base else f"{notes}\n"
    return out


def validate_mapping(mapping: object, objectives: object, rule_ids: object = None) -> list[str]:
    """Return a list of problems: bad shape, IDs absent from objectives.yml and
    bad per-rule overrides. ``rule_ids`` (when given) are the known Sigma rule
    ids; an override for any other id is an error."""
    if not isinstance(mapping, dict):
        return ["mapping is not a YAML mapping"]
    try:
        valid = {
            "secplus": set(objectives["secplus"]["objectives"]),
            "isc2cc": {int(k) for k in objectives["isc2cc"]["domains"]},
            "nist": set(objectives["nist_800_53"]["controls"]),
            "cis": set(objectives["cis_v8"]["safeguards"]),
        }
    except (KeyError, TypeError, ValueError):
        return ["objectives.yml is malformed: needs secplus.objectives, isc2cc.domains, "
                "nist_800_53.controls and cis_v8.safeguards"]
    known_rules = {str(r) for r in rule_ids} if rule_ids is not None else None
    errors = []
    if not isinstance(mapping.get("techniques"), dict) or not mapping["techniques"]:
        errors.append("mapping techniques: section missing or not a mapping")
    for section in ("tactics", "techniques", "rules"):
        block = mapping.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            if section != "techniques":
                errors.append(f"{section}: section is not a mapping")
            continue
        for key, entry in block.items():
            if not isinstance(entry, dict):
                errors.append(f"{section}.{key}: entry is not a mapping")
                continue
            if section == "rules":
                if known_rules is not None and str(key) not in known_rules:
                    errors.append(f"{section}.{key}: override for unknown rule id")
                if entry.get("mode", "replace") not in _MODES:
                    errors.append(f"{section}.{key}.mode: must be one of {', '.join(_MODES)}")
            for field, ok in valid.items():
                values = entry.get(field, [])
                if not isinstance(values, list):
                    errors.append(f"{section}.{key}.{field}: must be a list")
                    continue
                for value in values:
                    try:
                        norm = int(value) if field == "isc2cc" else str(value)
                    except (TypeError, ValueError):
                        errors.append(f"{section}.{key}.{field}: unknown ID {value!r}")
                        continue
                    if field == "nist":
                        norm = norm.lower()
                    if norm not in ok:
                        errors.append(f"{section}.{key}.{field}: unknown ID {value!r}")
            if section == "techniques":
                for field in _TEXT_FIELDS:
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


def _oneline(text: object) -> str:
    return " ".join(str(text).split())


def _read_yaml(path: Path, label: str | None = None):
    """Load YAML; any read/parse problem becomes a one-line TaggerError."""
    label = label or path.name
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise TaggerError(f"{label}: invalid YAML: {_oneline(exc)}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise TaggerError(f"{label}: cannot read: {_oneline(exc)}") from None


def _known_rule_ids(rule_dir: Path) -> set[str]:
    ids = set()
    for path in rule_dir.glob("*.yml"):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError, UnicodeDecodeError):
            continue  # reported when that file itself is processed
        if isinstance(rule, dict) and rule.get("id") is not None:
            ids.add(str(rule["id"]))
    return ids


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SentinelForge compliance tagger. mapping.yml may hold a top-level "
        "'rules:' section keyed by rule id (UUID) with per-rule overrides of a technique "
        "entry (same fields); the override wins per field; tag lists are replaced by "
        "default or unioned with 'mode: add'; an unknown rule id is a mapping error "
        "(exit 2).",
        epilog="Exit codes: 0 ok, 1 drift, 2 bad input or mapping (one-line error).",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 if rules/COVERAGE.md drift")
    mode.add_argument("--write", action="store_true", help="rewrite tags, notes and COVERAGE.md")
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING)
    parser.add_argument("--objectives", type=Path, default=DEFAULT_OBJECTIVES)
    parser.add_argument("--coverage", type=Path, default=DEFAULT_COVERAGE)
    parser.add_argument(
        "--files", nargs="+", type=Path, metavar="PATH",
        help="only check/write these rule files (COVERAGE.md is then neither checked nor written)",
    )
    parser.add_argument(
        "--allow-untagged", action="store_true",
        help="with --check: rules without any cert/nist/cis tag are warnings, not drift; "
        "malformed tags and drift in already-tagged rules still fail",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.allow_untagged and not args.check:
        parser.error("--allow-untagged is only valid with --check")
    try:
        return _run(args)
    except TaggerError as exc:
        print(f"error: {_oneline(exc)}", file=sys.stderr)
        return 2


def _run(args: argparse.Namespace) -> int:
    mapping = _read_yaml(args.mapping, f"mapping {args.mapping}")
    objectives = _read_yaml(args.objectives, f"objectives {args.objectives}")
    problems = validate_mapping(mapping, objectives, _known_rule_ids(args.rules_dir))
    if problems:
        for p in problems:
            print(f"mapping error: {_oneline(p)}", file=sys.stderr)
        return 2

    if args.files:
        paths = list(args.files)
        for path in paths:
            if not path.is_file():
                raise TaggerError(f"{path}: no such rule file")
    else:
        paths = sorted(args.rules_dir.glob("*.yml"))

    originals, tagged, done, skipped = [], [], [], []
    for path in paths:
        rule = None
        try:
            rule = _read_yaml(path)
            new = tag_rule(rule, mapping)
        except UnmappedTechniqueError as exc:
            if args.allow_untagged and not has_compliance_tags(rule):
                print(f"warning: {path.name}: untagged and not mappable ({_oneline(exc)})",
                      file=sys.stderr)
                skipped.append(path)
                continue
            raise TaggerError(f"{path.name}: {exc}") from None
        except TaggerError as exc:
            if str(exc).startswith(f"{path.name}:"):
                raise
            raise TaggerError(f"{path.name}: {exc}") from None
        if args.allow_untagged and not has_compliance_tags(rule):
            print(f"warning: {path.name}: no compliance tags yet (allowed by --allow-untagged)",
                  file=sys.stderr)
            skipped.append(path)
            continue
        done.append(path)
        originals.append(rule)
        tagged.append(new)

    drift = [p.name for p, o, n in zip(done, originals, tagged) if o != n]
    check_coverage = not args.files and not skipped
    coverage = coverage_markdown(originals, mapping) if check_coverage else None
    cov_drift = False
    if check_coverage:
        cov_current = args.coverage.read_text(encoding="utf-8") if args.coverage.exists() else None
        cov_drift = cov_current != coverage

    if args.check:
        for name in drift:
            print(f"drift: {name} needs --write", file=sys.stderr)
        if cov_drift:
            print(f"drift: {args.coverage} is out of date", file=sys.stderr)
        if skipped and not args.files:
            print("warning: COVERAGE.md not compared while untagged rules exist", file=sys.stderr)
        return 1 if drift or cov_drift else 0

    for path, old, new in zip(done, originals, tagged):
        if old != new:  # semantically correct files are never rewritten
            path.write_bytes(dump_rule(new).encode("utf-8"))
    if cov_drift:
        args.coverage.parent.mkdir(parents=True, exist_ok=True)
        args.coverage.write_bytes(coverage.encode("utf-8"))
    cov_msg = "skipped (--files)" if args.files else ("updated" if cov_drift else "unchanged")
    print(f"tagged {len(drift)} rule(s); coverage {cov_msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
