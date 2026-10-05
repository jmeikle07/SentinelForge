"""Single source of truth for detection coverage: what the shipped Sigma rules actually tag.

State files (state/seen_techniques.json) only contribute per-technique metadata (confidence,
deployment time, name) when they have an entry; nothing is invented for techniques they lack.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

# ATT&CK Enterprise tactics in kill-chain order (hyphenated, as the dashboard and state use them).
TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]
_TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class CoverageError(RuntimeError):
    """A rule file could not be parsed; coverage would be silently understated."""


def _tag_list(rule: Any) -> list[str]:
    tags = rule.get("tags") if isinstance(rule, dict) else None
    return [str(t) for t in tags] if isinstance(tags, list) else []


def rule_techniques(rules_dir: Path) -> dict[str, dict]:
    """{technique id: {"tactics": [...], "rules": n}} from every active rule under rules_dir."""
    rules_dir = Path(rules_dir)
    found: dict[str, dict] = {}
    paths = sorted([*rules_dir.glob("*.yml"), *rules_dir.glob("*.yaml")])
    for path in paths:
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise CoverageError(f"cannot read rule {path.name}: {exc}") from exc
        if not isinstance(rule, dict) or str(rule.get("status", "")).lower() == "deprecated":
            continue
        tags = _tag_list(rule)
        tactics = {t[7:].replace("_", "-") for t in tags if t.startswith("attack.")} & set(TACTICS)
        for tag in tags:
            m = _TECHNIQUE_TAG.match(tag)
            if m:
                entry = found.setdefault(m.group(1).upper(), {"tactics": set(), "rules": 0})
                entry["tactics"] |= tactics
                entry["rules"] += 1
    return {tid: {"tactics": sorted(e["tactics"], key=TACTICS.index), "rules": e["rules"]}
            for tid, e in found.items()}


def covered(rules_dir: Path, seen: dict | None = None) -> dict[str, dict]:
    """Rule-derived coverage merged with whatever metadata `seen` (state) holds for each technique."""
    seen = seen if isinstance(seen, dict) else {}
    out = {}
    for tid, base in rule_techniques(rules_dir).items():
        meta = seen.get(tid) if isinstance(seen.get(tid), dict) else {}
        out[tid] = {
            **base,
            "technique_name": meta.get("technique_name"),
            "confidence": (meta.get("confidence") or None),
            "deployed_at": (meta.get("deployed_at") or None),
        }
    return out
