#!/usr/bin/env python3
"""
SentinelForge - rule efficacy counter.

For every technique the engine has deployed a detection rule for, ask Elasticsearch how
many REAL security alerts that rule has produced, and when it first and last fired.
Writes state/rule_efficacy.json. Reports honestly: rules that fired vs rules still dormant.

One aggregation request covers all rules. No invented data: counts come straight
from the live alerts index.
"""
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from lab import config, es, http

log = logging.getLogger("sf.efficacy")

HERE = Path(__file__).resolve().parent
STATE_DIR = HERE / "state"
# Stable alias that Kibana maintains over the backing .internal.alerts-security.alerts-default-* indices.
ALERTS_INDEX = ".alerts-security.alerts-default"


def _tag(tech_id):
    return "attack." + tech_id.lower()


def fires_for_techniques(session, tech_ids):
    """Return {tech_id: (count, first_fired, last_fired)} using a single terms aggregation.

    Raises lab.es.SearchError if Elasticsearch is unreachable or returns an error.
    """
    tech_ids = list(tech_ids)
    tags = sorted({_tag(t) for t in tech_ids})
    body = {
        "size": 0,
        "query": {"terms": {"kibana.alert.rule.tags": tags}},
        "aggs": {"by_tag": {
            "terms": {"field": "kibana.alert.rule.tags", "include": tags, "size": max(len(tags), 1)},
            "aggs": {
                "first": {"min": {"field": "@timestamp"}},
                "last": {"max": {"field": "@timestamp"}},
            },
        }},
    }
    resp = es.search(session, ALERTS_INDEX, body)
    try:
        buckets = resp["aggregations"]["by_tag"]["buckets"]
    except (KeyError, TypeError) as exc:
        raise es.SearchError(f"unexpected aggregation response: {exc}") from exc
    by_tag = {b["key"]: b for b in buckets}
    out = {}
    for tech in tech_ids:
        b = by_tag.get(_tag(tech))
        if b is None:
            out[tech] = (0, None, None)
        else:
            out[tech] = (b.get("doc_count", 0),
                         (b.get("first") or {}).get("value_as_string"),
                         (b.get("last") or {}).get("value_as_string"))
    return out


def main():
    seen_path = STATE_DIR / "seen_techniques.json"
    if not seen_path.exists():
        print("no seen_techniques.json found")
        return 1
    seen = json.loads(seen_path.read_text())

    try:
        fires = fires_for_techniques(http.session(), seen)
        err = None
    except (es.SearchError, config.ConfigError) as exc:
        log.error("efficacy query failed: %s", exc)
        fires, err = {}, str(exc)

    results = {}
    fired, dormant, errors = 0, 0, 0
    for tech_id, meta in seen.items():
        if err:
            errors += 1
            results[tech_id] = {"error": err}
            continue
        count, first, last = fires[tech_id]
        results[tech_id] = {
            "technique_name": meta.get("technique_name"),
            "tactic": meta.get("tactic"),
            "rule_id": meta.get("rule_id"),
            "deployed_at": meta.get("deployed_at"),
            "fire_count": count,
            "first_fired": first,
            "last_fired": last,
        }
        if count > 0:
            fired += 1
        else:
            dormant += 1

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alerts_index": ALERTS_INDEX,
        "total_rules": len(seen),
        "rules_fired": fired,
        "rules_dormant": dormant,
        "rules_error": errors,
        "by_technique": results,
    }
    (STATE_DIR / "rule_efficacy.json").write_text(json.dumps(out, indent=2))

    print("\n  SentinelForge rule efficacy")
    print(f"  {'-'*46}")
    print(f"  rules deployed : {len(seen)}")
    print(f"  have fired     : {fired}")
    print(f"  still dormant  : {dormant}")
    if errors:
        print(f"  query errors   : {errors} ({err})")
    print(f"  {'-'*46}")
    ranked = sorted(
        [(t, r) for t, r in results.items() if "fire_count" in r],
        key=lambda x: x[1]["fire_count"], reverse=True)
    for t, r in ranked:
        if r["fire_count"] > 0:
            print(f"  {t:<12} {r['fire_count']:>6} fires   last: {(r['last_fired'] or '')[:16]}   {r['technique_name']}")
    print("\n  dormant (never fired):")
    for t, r in ranked:
        if r["fire_count"] == 0:
            print(f"  {t:<12}      0          {r['technique_name']}")
    print("\n  wrote state/rule_efficacy.json\n")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
