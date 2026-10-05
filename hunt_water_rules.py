#!/usr/bin/env python3
"""
hunt_water_rules.py — Hunt-side reader for Water's Sigma detection rules

Phase 6.C integration: gives Hunt visibility into what Water rules cover the
current attacker's likely ATT&CK techniques. Renders as a new RULES bucket
between EXTERNAL and PIVOTS.

CRITICAL DIFFERENCES vs the Water-side bridge:
  - Hunt is READ-ONLY here. Never modifies, deletes, or executes Water rules.
  - No safety gating needed (no closed-loop risk — Hunt just displays metadata).
  - No LLM involvement (no hallucination risk — just YAML parsing).
  - Hunt-triggered rules in pending_review state are surfaced with their status
    so the analyst can see them too (transparency: "Water already generated
    this from your last hunt, awaiting your review").

The technique inference reuses water_hunt_trigger's honeypot-to-technique map (_mapping_for)
so both pillars use the same honeypot→ATT&CK semantics — no drift possible.
"""

import logging
import re
from pathlib import Path

import yaml

from water_hunt_trigger import _mapping_for

log = logging.getLogger(__name__)

# Where Water writes rules (anchored to this file so the cwd never matters)
_ROOT                 = Path(__file__).resolve().parent
SIGMA_DIR             = _ROOT / "detections" / "sigma"
SIGMA_HUNT_DIR        = _ROOT / "detections" / "sigma" / "hunt-triggered"

# Parsed-rule cache keyed by path; an entry is valid while (mtime_ns, size) is unchanged.
_PARSE_CACHE: dict = {}


def _infer_techniques_from_observed(observed: dict) -> list:
    """
    Return a list of ATT&CK technique IDs that this attacker's honeypot mix
    suggests. Uses water_hunt_trigger's mapping so both pillars stay aligned.
    Returns top 3 techniques by cumulative event volume, with the dominant
    one first. May be empty for IOCs with no honeypot activity (e.g. DROP-only).
    """
    honeypots = observed.get("honeypots", []) or []
    if not honeypots:
        return []

    technique_totals = {}
    for hp in honeypots:
        name = hp.get("name") or ""
        count = hp.get("count", 0) or 0
        mapping = _mapping_for(name)
        if not mapping:
            continue
        tid = mapping["id"]
        if tid not in technique_totals:
            technique_totals[tid] = {"id": tid, "name": mapping["name"], "events": 0}
        technique_totals[tid]["events"] += count

    sorted_techniques = sorted(
        technique_totals.values(),
        key=lambda t: t["events"],
        reverse=True,
    )
    return [t["id"] for t in sorted_techniques[:3]]


_TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class RuleLoadError(RuntimeError):
    """One or more production rule files could not be read or parsed."""


def _parse_rule_text(path: Path, text: str) -> dict:
    """Parse one rule file's text. Returns {"meta": display dict, "raw": parsed rule}.
    Raises ValueError for anything that is not a valid YAML mapping: a file that does not
    parse is NEVER partially recovered, so a broken rule can never count as coverage
    (same rule as lab.coverage, which raises CoverageError)."""
    triggered_by_hunt_id = None
    triggered_by_ioc = None
    for line in text.splitlines():
        # Provenance hints live in the leading comment block of hunt-triggered rules
        if line.startswith("# Triggered by hunt_id:"):
            triggered_by_hunt_id = line.split(":", 1)[1].strip()
        elif line.startswith("# IOC:"):
            triggered_by_ioc = line.split(":", 1)[1].strip()
        elif not (line.startswith("#") or line.strip() == ""):
            break
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"not valid YAML ({exc})") from exc
    if not isinstance(parsed, dict):
        raise ValueError("not a YAML mapping")

    tags = parsed.get("tags") if isinstance(parsed.get("tags"), list) else []
    techniques = []
    for tag in tags:
        m = _TECHNIQUE_TAG.match(tag) if isinstance(tag, str) else None
        if m:
            techniques.append(m.group(1).upper())
    meta = {
        "path":                  str(path),
        "filename":              path.name,
        "title":                 parsed.get("title", path.stem),
        "id":                    parsed.get("id"),
        "status":                parsed.get("status", "?"),
        "level":                 parsed.get("level", "?"),
        "techniques":            techniques,
        "is_hunt_triggered":     "hunt-triggered" in str(path),
        "triggered_by_hunt_id":  triggered_by_hunt_id,
        "triggered_by_ioc":      triggered_by_ioc,
    }
    return {"meta": meta, "raw": parsed}


def _load_entry(path: Path) -> dict:
    """Cached loader shared by every consumer: a file is read and parsed once until its
    (mtime, size) changes. Returns {"meta", "raw", "error"}; error is a short reason when
    the file cannot be used (and is logged once, when first parsed)."""
    try:
        st = path.stat()
    except OSError as exc:
        log.warning("cannot stat rule file %s: skipping it (%s)", path, exc)
        return {"meta": None, "raw": None, "error": f"cannot stat: {exc}"}
    stamp = (st.st_mtime_ns, st.st_size)
    hit = _PARSE_CACHE.get(path)
    if hit is not None and hit[0] == stamp:
        return hit[1]
    try:
        entry = {**_parse_rule_text(path, path.read_text(encoding="utf-8")), "error": None}
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        log.warning("rule file %s unusable, skipping it (not counted as coverage): %s", path, exc)
        entry = {"meta": None, "raw": None, "error": str(exc)}
    _PARSE_CACHE[path] = (stamp, entry)
    return entry


def _iter_entries(*dirs: Path):
    """The one place rule files are listed: (path, entry) for *.yml and *.yaml in each
    existing directory, sorted. A directory that cannot be listed raises OSError."""
    for base in dirs:
        if not base.is_dir():
            continue
        for path in sorted([*base.glob("*.yml"), *base.glob("*.yaml")]):
            yield path, _load_entry(path)


def _is_deprecated(rule: dict) -> bool:
    return str(rule.get("status", "")).lower() == "deprecated"


def load_active_rules(rules_dir=None) -> list:
    """Full parsed production rules (detections/sigma/*.yml|yaml) that are not deprecated.

    Feeds sf_safety's layer-8 disagreement check. A missing directory means "no rules"
    ([]); an unreadable or unparseable file raises RuleLoadError listing every offender,
    so the caller can decide (the Water gate fails closed: it cannot prove an unreadable
    rule is not an allowlist for the IOC)."""
    base = Path(rules_dir) if rules_dir is not None else SIGMA_DIR
    if not base.is_dir():
        log.warning("rules dir %s does not exist: no existing rules to check", base)
        return []
    try:
        entries = list(_iter_entries(base))
    except OSError as exc:
        raise RuleLoadError(f"cannot list {base}: {exc}") from exc
    bad = [p.name for p, e in entries if e["error"]]
    if bad:
        raise RuleLoadError(f"unreadable rule files: {', '.join(bad)}")
    return [e["raw"] for _, e in entries if not _is_deprecated(e["raw"])]


def _technique_matches(query: str, rule_tech: str) -> bool:
    """Exact on sub-technique. A parent query (T1110) matches the parent and all of its
    sub-techniques; a sub-technique query (T1110.001) matches only itself and a rule tagged
    with the bare parent (which covers it), never a sibling (T1110.003)."""
    if query == rule_tech:
        return True
    if "." not in query:
        return rule_tech.split(".")[0] == query
    return rule_tech == query.split(".")[0]


def find_rules_for_techniques(technique_ids: list) -> list:
    """
    Walk the detections/sigma/ tree (production + hunt-triggered) and return
    non-deprecated rules tagged with any of the given technique IDs.

    Matching is case-insensitive and exact on sub-techniques (see _technique_matches).
    Files that fail to parse are logged and skipped, never counted.
    """
    queries = [str(t).upper() for t in (technique_ids or [])]
    if not queries:
        return []
    matches = []
    for _path, entry in _iter_entries(SIGMA_DIR, SIGMA_HUNT_DIR):
        if entry["error"] or _is_deprecated(entry["raw"]):
            continue
        meta = entry["meta"]
        if any(_technique_matches(q, rt) for q in queries for rt in meta["techniques"]):
            matches.append(meta)
    return matches


def bucket_rules(observed: dict, current_ioc: str = None) -> dict:
    """
    Main entry point — Hunt calls this and gets a dict to render.

    Returns:
      {
        "inferred_techniques": [...],
        "matching_rules":      [{rule dict}, ...],
        "self_triggered_rules": [...]   # rules specifically triggered by hunts of THIS IOC
      }
    """
    techniques = _infer_techniques_from_observed(observed)
    matches = find_rules_for_techniques(techniques)

    # Surface separately if any matching rule was triggered by a previous hunt of this exact IOC
    self_triggered = []
    if current_ioc:
        for rule in matches:
            if rule.get("triggered_by_ioc") == current_ioc:
                self_triggered.append(rule)

    return {
        "inferred_techniques":  techniques,
        "matching_rules":       matches,
        "self_triggered_rules": self_triggered,
    }


# ── Self-test when run directly ───────────────────────────────────────────────

if __name__ == "__main__":
    """
    Run as: python hunt_water_rules.py
    Smoke-tests technique inference and rule scanning against real disk state.
    """
    print("== hunt_water_rules self-test ==\n")

    print("Test 1: technique inference from 77.83.240.70 honeypot mix")
    sample_observed = {
        "honeypots": [
            {"name": "P0f", "count": 395966},
            {"name": "Suricata", "count": 137470},
            {"name": "Honeytrap", "count": 64853},
            {"name": "Cowrie", "count": 383},
        ],
    }
    techniques = _infer_techniques_from_observed(sample_observed)
    print(f"  inferred techniques: {techniques}")
    assert "T1046" in techniques, f"expected T1046 in {techniques}"
    print("  ✓ T1046 (Network Service Scanning) correctly inferred\n")

    print("Test 2: rule scanning")
    result = bucket_rules(sample_observed, current_ioc="77.83.240.70")
    print(f"  inferred_techniques:    {result['inferred_techniques']}")
    print(f"  matching_rules:         {len(result['matching_rules'])} rules")
    print(f"  self_triggered_rules:   {len(result['self_triggered_rules'])} rules")
    for rule in result["matching_rules"][:5]:
        print(f"    · {rule['title'][:60]:<60} [{rule['status']}] {rule['techniques']}")
        if rule.get("is_hunt_triggered"):
            print(f"        (hunt-triggered by {rule.get('triggered_by_ioc', '?')})")
    print()

    print("Test 3: empty observed returns empty result")
    empty = bucket_rules({}, "anything")
    assert empty["inferred_techniques"] == []
    assert empty["matching_rules"] == []
    assert empty["self_triggered_rules"] == []
    print("  ✓ empty input handled cleanly\n")

    print("ALL CHECKS PASSED")
