# SentinelForge architecture

Author: Jahsean Meikle

This document describes the components and how data moves between them. It describes the design of the code in this repository; it does not claim the system is deployed anywhere. For what has and has not been verified, see "Testing and what is not verified" in the [README](../README.md).

## Components

| Layer | Files | Responsibility |
|---|---|---|
| Shared library | `lab/config.py`, `lab/http.py`, `lab/ecs.py`, `lab/state.py`, `lab/es.py`, `lab/kibana_rule.py` | Settings from env; one HTTP session factory (timeout, retry on 429/502/503/504, TLS verification on unless `LAB_INSECURE_TLS=1`); the single Sigma to ECS conversion pipeline; atomic JSON state files that quarantine corrupt files; `search_after` paging; Kibana detection-rule payload builder. |
| Detection content | `detections/sigma/*.yml`, `docs/compliance/mapping.yml`, `docs/compliance/objectives.yml` | Sigma rules plus the mapping that drives their ATT&CK, Security+, ISC2 CC, NIST 800-53 and CIS v8 tags and defender notes. |
| Compliance tooling | `tools/tag_compliance.py`, `tools/readme_tables.py` | Tag rules from the mapping (`--write`), fail on drift (`--check`), generate `docs/compliance/COVERAGE.md` and the README tables. |
| Rule engine | `generate_rule.py`, `water_hunt_trigger.py`, `validate_rule.py`, `approve.py`, `deploy_rule.py` | Propose a rule from observed telemetry, validate it, hold it for a human, deploy it. |
| Hunt | `sf_hunt.py`, `sf_safety.py` | IOC enrichment from several sources with a deterministic verdict; safety gates that decide when a hunt verdict may trigger rule generation. |
| Web | `sf_web.py`, `web/` | FastAPI app: hunt, engine and review dashboards, JSON API, token-gated approve/reject. |
| Measurement | `rule_efficacy.py`, `generate_heatmap.py` | Alerts per deployed rule from one aggregation; ATT&CK Navigator layer. |
| Alerting | `elastalert/` | ElastAlert 2 templates, rendered with `envsubst` by `elastalert/run.sh`. |
| CI | `.github/workflows/test.yml`, `.github/workflows/deploy-detections.yml` | Offline tests on hosted runners; validate then deploy on a self-hosted runner for pushes to `main` that touch `detections/sigma/`. |
| Scheduling | `run_efficacy.sh`, `run_engine.sh`, `scheduler/*.plist` | Optional periodic efficacy refresh and gated engine run (macOS launchd). |

## Data flow

```
                    +--------------------+
 endpoint telemetry |  Elasticsearch     |  <---- ElastAlert 2 reads Kibana alerts
 (Sysmon via        |  logs-*, alerts    |         from .alerts-security.alerts-default
  Elastic Agent) -> |                    |  ----> email
                    +----+----------+----+
                         |          ^
        events (paged)   |          | alerts (one terms aggregation)
                         v          |
  +----------------------------+  +-------------------+
  | generate_rule.py           |  | rule_efficacy.py  |--> state/rule_efficacy.json
  |  LLM proposes Sigma rule   |  +-------------------+
  +-------------+--------------+
                | WATER_REVIEW_GATE=true
                v
   detections/pending/  +  state/pending_rules.json
                |
                |  human: approve.py  or  sf_web /review (X-Admin-Token)
                v
   detections/sigma/<rule>.yml  --git push-->  GitHub
                                                 |
                       +-------------------------+----------------------+
                       | pull_request / push                            | push to main
                       v                                                v
                 test.yml (hosted runner)                 deploy-detections.yml (self-hosted)
                 pytest, tag_compliance --check             validate job: validate_rule.py
                                                              1 YAML lint
                                                              2 Sigma -> Lucene (lab.ecs)
                                                              3 backtest vs Elasticsearch, 7 days
                                                              4 Claude / Gemini / Ollama vote
                                                              5 self-heal, max 3 attempts
                                                            deploy job (only if validate succeeded):
                                                              deploy_rule.py -> Kibana detection engine
```

### Rule lifecycle

1. **Proposal.** `generate_rule.py` queries recent events, extracts indicators, asks an LLM for the ATT&CK technique and a Sigma rule using ECS field names. `water_hunt_trigger.py` is a second entry path: high-confidence `sf_hunt` verdicts that pass the `sf_safety` gates can trigger a proposal, marked `pending_review`.
2. **Hold.** With `WATER_REVIEW_GATE=true` the rule is written to `detections/pending/` and queued in `state/pending_rules.json`. Nothing reaches the SIEM.
3. **Review.** A person uses `approve.py` or the `/review` page. The page shows each pending rule in plain language alongside the three-model vote receipt. Approving calls the same save-and-push path as the ungated flow; rejecting discards. The web routes require `LAB_ADMIN_TOKEN` and a UUID `rule_id`.
4. **Validate.** On push to `main`, CI runs `validate_rule.py` for each changed rule. A failed backtest, including Elasticsearch being unreachable, is a failed validation. Voters run concurrently; a voter whose API key is missing is skipped with a warning. Failing rules are rewritten from the voters' feedback up to three times, then the circuit breaker emails and stops.
5. **Deploy.** The deploy job runs only after validation succeeds. `deploy_rule.py` converts the rule, builds the payload with `lab.kibana_rule.build_payload`, creates it in Kibana, and on a 409 conflict updates it with `PUT` using the `rule_id` in the body. Rule `id` UUIDs are stable because deployed Kibana rules key on them.
6. **Measure and alert.** `rule_efficacy.py` reports which deployed rules have fired. ElastAlert 2 emails on active Kibana alerts.

### Compliance tagging flow

`docs/compliance/mapping.yml` (keyed by technique and tactic) and `docs/compliance/objectives.yml` (official objective titles with source and retrieval date) feed `tools/tag_compliance.py`. `tag_rule` is pure and idempotent: it adds `cert.secplus.*`, `cert.isc2cc.d*`, `nist.800-53.*` and `cis.v8.*` tags and a "Defender notes" block (hardening, IR step, risk treatment) to each rule. An unmapped technique or malformed tag is a clear error, not a crash. `--check` runs in CI and fails on drift, so rules, `COVERAGE.md` and the mapping cannot silently diverge.

### State

Runtime state is JSON under `state/` (pending rules, validations, hunt log, efficacy, rate-limit counters). `lab.state` writes atomically (temporary file plus `os.replace`, with a lock). A corrupt file is moved aside to `<name>.corrupt` and raises `StateCorrupt` instead of being overwritten with an empty list. The files committed under `state/` are example runtime snapshots from earlier runs; they contain no secrets and may be regenerated or deleted.

## Trust boundaries and secrets

- The web app and the engine read credentials from environment variables (`.env` locally, repository secrets in CI). Nothing secret is in a tracked file.
- Browser to `sf_web.py`: state-changing routes need `X-Admin-Token`; hunting is rate limited per client address (behind a reverse proxy, use the proxy's per-client limiter as well).
- Pipeline to Elasticsearch/Kibana: TLS verification on; API key in `ELASTIC_API_KEY`.
- CI: pull requests run only on hosted runners with read-only permissions and no secrets. The self-hosted runner, which can reach the lab network, only runs for pushes to `main`.
