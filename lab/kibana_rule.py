"""Build the Kibana detection-engine rule payload from a parsed Sigma rule."""
from __future__ import annotations

from typing import Any

INTERVAL = "5m"
LOOKBACK = "now-6m"  # interval + 1m buffer: no overlap-driven duplicate alerts, no gaps
INDICES = ["logs-*", "winlogbeat-*", "filebeat-*"]

_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium",
             "low": "low", "informational": "low"}
_RISK = {"critical": 99, "high": 73, "medium": 47, "low": 21}


def build_payload(rule: dict, queries: list[str], author: str) -> dict[str, Any]:
    if not queries:
        raise ValueError("at least one query is required")
    query = queries[0] if len(queries) == 1 else " OR ".join(f"({q})" for q in queries)
    severity = _SEVERITY.get(rule.get("level", "medium"), "medium")
    return {
        "type": "query",
        "language": "lucene",
        "query": query,
        "name": rule.get("title", "Unnamed Rule"),
        "description": rule.get("description", "No description provided."),
        "severity": severity,
        "risk_score": _RISK.get(severity, 47),
        "enabled": True,
        "from": LOOKBACK,
        "interval": INTERVAL,
        "max_signals": 100,
        "tags": [str(t) for t in rule.get("tags", [])],
        "references": rule.get("references", []),
        "author": [author] if author else [],
        "index": list(INDICES),
        "rule_id": str(rule.get("id", "")),
        "false_positives": rule.get("falsepositives", []),
        "immutable": False,
        "version": 1,
    }
