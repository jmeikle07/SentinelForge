"""Build the Kibana detection-engine rule payload from a parsed Sigma rule."""
from __future__ import annotations

import re
from typing import Any, Iterable

INTERVAL = "5m"
LOOKBACK = "now-6m"  # interval + 1m buffer: no overlap-driven duplicate alerts, no gaps
INDICES = ["logs-*", "winlogbeat-*", "filebeat-*"]

_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium",
             "low": "low", "informational": "low"}
_RISK = {"critical": 99, "high": 73, "medium": 47, "low": 21}

# Fields the engine owns and may overwrite on redeploy. Everything else on an existing rule
# (enabled, exceptions_list, actions, throttle, note, ...) belongs to the analyst and is never
# sent on update.
ENGINE_OWNED_FIELDS = ("name", "description", "query", "language", "severity", "risk_score",
                       "tags", "references", "author", "false_positives", "index", "from",
                       "interval", "max_signals", "type")

_TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def technique_tags(tags: Iterable[Any] | None) -> set[str]:
    """Lower-cased `attack.tNNNN[.NNN]` tags (technique ids, not tactics)."""
    out = set()
    for t in _as_list(tags):
        s = str(t).strip().lower() if t is not None else ""
        if _TECHNIQUE_TAG.match(s):
            out.add(s)
    return out


def build_payload(rule: dict, queries: list[str], author: str) -> dict[str, Any]:
    if not queries:
        raise ValueError("at least one query is required")
    rule_id = str(rule.get("id") or "").strip()
    if not rule_id:
        raise ValueError("rule has no id")
    query = queries[0] if len(queries) == 1 else " OR ".join(f"({q})" for q in queries)
    level = str(rule.get("level") or "medium").strip().lower()
    severity = _SEVERITY.get(level, "medium")
    return {
        "type": "query",
        "language": "lucene",
        "query": query,
        "name": rule.get("title") or "Unnamed Rule",
        "description": rule.get("description") or "No description provided.",
        "severity": severity,
        "risk_score": _RISK.get(severity, 47),
        "enabled": True,  # creation only; build_update_payload never forwards it
        "from": LOOKBACK,
        "interval": INTERVAL,
        "max_signals": 100,
        "tags": [str(t) for t in _as_list(rule.get("tags"))],
        "references": [str(r) for r in _as_list(rule.get("references"))],
        "author": [author] if author else [],
        "index": list(INDICES),
        "rule_id": rule_id,
        "false_positives": [str(f) for f in _as_list(rule.get("falsepositives"))],
    }


def build_update_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """PATCH body: rule_id plus only the engine-owned fields."""
    body = {k: payload[k] for k in ENGINE_OWNED_FIELDS if k in payload}
    body["rule_id"] = payload["rule_id"]
    return body
