# SentinelForge architecture

Author: Jahsean Meikle

This document describes the components and how data moves between them. It describes the design of the code in this repository; it does not claim the system is deployed anywhere. For what has and has not been verified, see "Known limitations and what is not verified" in the [README](../README.md#known-limitations-and-what-is-not-verified).

## Components

| Layer | Files | Responsibility |
|---|---|---|
| Shared library | `lab/config.py`, `lab/http.py`, `lab/ecs.py`, `lab/state.py`, `lab/es.py`, `lab/kibana_rule.py`, `lab/coverage.py` | Settings from env; one HTTP session factory (default timeout, retry on 429/502/503/504 for idempotent methods only, `Retry-After` capped at 30 s, TLS verification on unless `LAB_INSECURE_TLS=1`); the single Sigma to ECS conversion pipeline with case-variant expansion; atomic JSON state files under a cross-process advisory lock that quarantine corrupt files; point-in-time (PIT) plus `search_after` paging that raises on partial or malformed pages; Kibana detection-rule payload builder and the list of engine-owned fields used for updates; ATT&CK coverage counted from the shipped rules (deprecated rules excluded). |
| Detection content | `detections/sigma/*.yml`, `docs/compliance/mapping.yml`, `docs/compliance/objectives.yml` | Sigma rules plus the mapping that drives their ATT&CK, Security+, ISC2 CC, NIST 800-53 and CIS v8 tags and defender notes. |
| Compliance tooling | `tools/tag_compliance.py`, `tools/readme_tables.py` | Tag rules from the mapping (`--write`), fail on drift (`--check`), generate `docs/compliance/COVERAGE.md` and the README tables. |
| Rule engine | `generate_rule.py`, `water_hunt_trigger.py`, `validate_rule.py`, `approve.py`, `deploy_rule.py`, `tools/redeploy_all.py` | Propose a rule from observed telemetry, validate it, hold it for a human, deploy it; bulk reconciliation of Kibana with the shipped rules (see [REDEPLOY.md](REDEPLOY.md)). |
| Hunt | `sf_hunt.py`, `sf_safety.py` | IOC enrichment from several sources with a deterministic verdict; safety gates that decide when a hunt verdict may trigger rule generation. |
| Web | `sf_web.py`, `web/` | FastAPI app: hunt, engine and review dashboards, JSON API, token-gated approve/reject. |
| Measurement | `rule_efficacy.py`, `generate_heatmap.py` | Alerts per deployed rule from one aggregation; ATT&CK Navigator layer. |
| Alerting | `elastalert/` | ElastAlert 2 templates, rendered with `envsubst` by `elastalert/run.sh`. |
| CI | `.github/workflows/test.yml`, `.github/workflows/deploy-detections.yml`, `tools/ci_changes.py`, `scripts/ci_*.sh` | Offline tests on hosted runners; plan, validate, heal and then deploy on a self-hosted runner for pushes to `main` that touch `detections/sigma/`. `ci_changes.py` works out changed, removed and retagged rules from the git diff. |
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
                 pytest, tag_compliance --check,            plan: tools/ci_changes.py (changed/removed/retagged)
                 readme_tables --check                      validate job: validate_rule.py
                                                              1 YAML lint
                                                              2 Sigma -> Lucene (lab.ecs)
                                                              3 backtest vs Elasticsearch, 7 days
                                                              4 Claude / Gemini / Ollama vote
                                                              5 self-heal, max 3 attempts
                                                            deploy job (only if validate succeeded):
                                                              deploy_rule.py -> Kibana detection engine
                                                              deploy_rule.py --delete <id> for removed rules
```

### Rule lifecycle

1. **Proposal.** `generate_rule.py` queries recent events, extracts indicators, asks an LLM for the ATT&CK technique and a Sigma rule using ECS field names. `water_hunt_trigger.py` is a second entry path: high-confidence `sf_hunt` verdicts that pass the `sf_safety` gates can trigger a proposal, marked `pending_review`.
2. **Hold.** With `WATER_REVIEW_GATE=true` the rule is written to `detections/pending/` and queued in `state/pending_rules.json`. Nothing reaches the SIEM.
3. **Review.** A person uses `approve.py` or the `/review` page. The page shows each pending rule in plain language alongside the three-model vote receipt. Approving publishes the rule (writes it to `detections/sigma/` and pushes) first and only then updates state, so a failed publish leaves the rule pending and retryable; rejecting discards. The web routes require `LAB_ADMIN_TOKEN` and a UUID `rule_id`.
4. **Validate.** On push to `main`, CI runs `validate_rule.py` for each changed rule. A failed backtest, including Elasticsearch being unreachable, is a failed validation. Voters run concurrently; a voter that is unreachable or has no API key is excluded with a warning, and at least two well-formed votes are required (a malformed vote is never an approval). Failing rules are rewritten from the voters' feedback, keeping the original id and technique tags, for at most three attempts, then the circuit breaker emails and stops.
5. **Deploy.** The deploy job runs only after validation succeeds. `deploy_rule.py` converts the rule, builds the payload with `lab.kibana_rule.build_payload`, creates it in Kibana, and on a 409 conflict reads the existing rule, checks that it is an earlier version of the same rule (a shared ATT&CK technique tag; a deliberate retag needs `--allow-retag`), and updates only the engine-owned fields with `PATCH`, so exceptions, actions and the enabled state set in Kibana are kept. A rule with `status: deprecated` is never created; if Kibana has it, it is disabled. Rule `id` UUIDs are stable because deployed Kibana rules key on them.
6. **Measure and alert.** `rule_efficacy.py` reports which deployed rules have fired. ElastAlert 2 emails on active Kibana alerts.

### Compliance tagging flow

`docs/compliance/mapping.yml` (keyed by technique and tactic) and `docs/compliance/objectives.yml` (official objective titles with source and retrieval date) feed `tools/tag_compliance.py`. `tag_rule` is pure and idempotent: it adds `cert.secplus.*`, `cert.isc2cc.d*`, `nist.800-53.*` and `cis.v8.*` tags and a "Defender notes" block (hardening, IR step, risk treatment) to each rule. An unmapped technique or malformed tag is a clear error, not a crash. `--check` runs in CI and fails on drift, so rules, `COVERAGE.md` and the mapping cannot silently diverge.

### State

Runtime state is JSON under `state/` (pending rules, validations, hunt log, last run, seen techniques, efficacy) and `state/sf/` (the hunt memory database, the trigger rate-limit file). `lab.state` writes atomically (temporary file plus `os.replace`) under a kernel advisory lock on a `<name>.lock` file (`msvcrt` on Windows, `flock` elsewhere), so separate processes cannot interleave a read-modify-write; the OS releases the lock if the holder dies. `lab.state.update` does the whole read-modify-write under the lock. Lock files are git-ignored runtime artefacts. The multi-process behaviour is tested with real subprocesses (`tests/test_state_multiprocess.py`). A corrupt file is moved aside to `<name>.corrupt` and raises `StateCorrupt` instead of being overwritten with an empty list. The files committed under `state/` are example runtime snapshots from earlier runs; they contain no secrets and may be regenerated or deleted.

## Case sensitivity

Sigma compares strings case-insensitively. `lab.ecs.convert` renders the literals into a Lucene `query_string`, and whether Elasticsearch then ignores case depends on the field mapping: ECS `keyword` fields (`process.name`, `registry.value`, `dns.question.name`, ...) and `wildcard` fields (`process.command_line`, `process.executable`, `file.path`, `registry.key` in the Elastic Agent mappings) are case-sensitive; only analysed `text` / `match_only_text` subfields fold case. Windows binaries, paths, registry keys, switches and DNS names are case-insensitive in practice (`HOSTNAME.EXE` on disk, `hostname.exe` in scripts, `reg SAVE`, `/Create`), so a rule written in one casing would silently miss the others. The lab's own mapping could not be queried offline, so the fix does not depend on it.

**What happens.** A late pipeline step in `lab/ecs.py` (`CaseVariantTransformation`, applied by `convert` and `convert_path`) expands each string literal on a defined field set into case variants: as written, lower, UPPER and Title (first letter of each word, after space, `\`, `/`, `:`, `-`; a `.` does not start a word, so `cmd.exe` becomes `Cmd.exe`), deduplicated. `startswith` / `endswith` / `contains` wildcards are kept, `contains|all` keeps its AND (each value becomes its own OR group), and hand-written variants in a rule (`Domain Admins` next to `domain admins`) collapse into the generated set. Rule YAML is not touched, so rule ids and sources do not change; only the deployed query grows.

**Fields covered** (`CASE_INSENSITIVE_FIELDS`): `process.{name,executable,command_line,working_directory,pe.original_file_name}`, the same under `process.parent.*`, `file.{name,path,directory,extension}`, `dll.{name,path}`, `registry.{path,key,value}`, `dns.question.name`, `{source,destination}.domain`, `user.{name,domain}` and the Sysmon-only `winlog.event_data.{Image,ParentImage,SourceImage,TargetImage,ImageLoaded,CommandLine,ParentCommandLine,CurrentDirectory,TargetFilename,TargetObject,PipeName,OriginalFileName,QueryName}`. Not touched: hashes, `event.code` / `event.action`, ports and IPs, `registry.data.strings` (the data written, where case can matter), `winlog.event_data.IntegrityLevel` (Sysmon emits a fixed vocabulary), free-text descriptions, hex fields, `|re` and `|cidr` values, base64 / wide values, and non-Windows log sources. `|cased` cannot occur: pySigma's Lucene backend raises `NotImplementedError` for it, and the step would skip it anyway.

**Bounds.** At most 4 variants per literal. At most 200 leaf clauses per generated query (`QUERY_CLAUSE_BUDGET`; `lab.ecs.clause_count` counts them). If a rule would exceed the budget, `convert` degrades in steps: as written + lower + UPPER; the same only for value lists of at most 10 entries; no expansion at all. Each degradation logs one warning naming the rule (`lab.ecs` logger). Of the 41 shipped rules, 39 get the full four variants and one (`T1595`, an IP rule) has nothing to expand; `T1035` (Svchost service-group allowlist, 144 `-k <group>` literals) keeps those as written and only its short lists are expanded (148 to 152 clauses). Across the shipped rules the mean clause count goes from 12.0 to 25.1 (max 152) and the mean query length from about 326 to 581 characters (max 4204).

**Switch.** `SF_CASE_VARIANTS=0` in the environment turns the step off (queries are then rendered verbatim, as before); it is read on every conversion and defaults to on. Use it to compare a deployed query with the old one when debugging.

**Residual risk.**
- Only the four variants are generated. A literal whose real spelling is CamelCase (`PowerShell.exe`, `WinRAR.exe`, a user typing `-InFile` against a rule with `-infile`) is matched only if it equals one of them; list such spellings in the rule or rely on a mapping that folds case.
- `contains`-style values are expanded per literal, not per event: `*Hello World*` does not match `Hello world`.
- Values whose case is meaningful (passwords, tokens, base64) on a covered field are expanded too; that only widens the match, and the rule text is the place to avoid it (use another field or a regex).
- Matching on fields outside the list above stays exactly as case-sensitive as the mapping makes it.
- Larger queries: the Lucene `max_clause_count` (`indices.query.bool.max_clause_count`) bounds clauses of a single boolean query and wildcard terms rewrite into more; with at most 200 leaves per query we are well below the default of 1024, but this was not exercised against the live cluster. Leading-wildcard terms (`*x*`) on `wildcard` fields are what the cluster already handles for these rules; on plain `keyword` fields they scan the terms dictionary, so the extra variants cost proportionally more per rule run.
- Not verified offline: the live mapping of the lab's indices, any `normalizer`, and Kibana's behaviour for very long rule queries (the longest generated query is about 4.2 kB). I could not browse the Elastic documentation from the environment this was built in; the statements about `query_string` rely on the documented behaviour that term-level queries on `keyword` fields are exact unless the field has a lowercase normalizer, and on `query_string` having no per-query case-insensitivity switch.

**Check the live index.** The first request shows how the field is mapped (`type`, and a `normalizer` on the keyword); the second pair shows whether a verbatim query ignores case (the counts are equal if the mapping already folds case, different if not; either way the converted queries now match all spellings):

```
GET logs-*/_mapping/field/process.name,process.command_line,registry.key

GET logs-*/_search
{"size": 0, "track_total_hits": true,
 "query": {"query_string": {"query": "process.name:hostname.exe"}}}
GET logs-*/_search
{"size": 0, "track_total_hits": true,
 "query": {"query_string": {"query": "process.name:HOSTNAME.EXE"}}}
```

To my knowledge ECS core defines the `.text` (`match_only_text`) multi-fields but no case-insensitive `.caseless` subfield (any such subfield would be an Elastic Agent / Endpoint mapping detail; this could not be checked offline), so nothing here depends on one being present.

## Trust boundaries and secrets

- The web app and the engine read credentials from environment variables (`.env` locally, repository secrets in CI). Nothing secret is in a tracked file.
- Browser to `sf_web.py`: the `Host` header must be in `SF_ALLOWED_HOSTS`; state-changing routes need `X-Admin-Token` (at least 16 characters, repeated failures lock the client out); hunting is `POST` only and rate limited per client address (behind a reverse proxy, see the proxy-header note in [SETUP.md](SETUP.md)). The read endpoints are unauthenticated.
- Hunt verdict to rule generation: only records with valid, high-trust `user` or `hunt` provenance pass `sf_safety.should_water_act_on_hunt`; missing provenance fails closed.
- LLM output to the repository: `generate_rule.validate_generated_sigma` validates and re-renders model output; the engine, not the model, sets `id`, `author`, `date` and `status`.
- Pipeline to Elasticsearch/Kibana: TLS verification on; API key in `ELASTIC_API_KEY`.
- CI: pull requests run only on hosted runners with read-only permissions and no secrets. The self-hosted runner, which can reach the lab network, only runs for pushes to `main`.
