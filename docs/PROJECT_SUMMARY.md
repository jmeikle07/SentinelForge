# SentinelForge: project summary

Author: Jahsean Meikle. This is a technical summary for a reviewer. It says what exists, why it is built that way, and where each claim can be checked. The [README](../README.md) has the commands and the full list of limitations.

## Problem

Detection rules usually live in a SIEM console: no history, no review, no tests, and no record of what each rule is for. This project keeps detections as Sigma files in git and treats them like code. Each rule is converted to an Elastic query, checked with tests, tagged with the ATT&CK technique it detects and the Security+ / ISC2 CC objectives, NIST 800-53 controls and CIS v8 safeguards it relates to, and deployed to Kibana through a gated pipeline. A second part, an LLM-assisted rule generator, proposes new rules from observed telemetry and is built so that its output cannot reach a repository or a SIEM without validation.

It is a lab project. Nothing here has been run against a live Elastic, Kibana, GitHub or LLM service; the tests simulate them.

## What was built

- 41 Sigma rule files for Windows telemetry (Sysmon-style fields), 28 ATT&CK techniques and sub-techniques covered. The counts are generated from the rule files by `tools/readme_tables.py`. Some of the 41 files are deprecated rules kept so Kibana can disable them.
- `lab/`: a small shared library for config, HTTP sessions, Sigma to ECS conversion, locked state files, paged Elasticsearch search, Kibana payloads and coverage counting.
- A rule pipeline: `generate_rule.py` (propose), `validate_rule.py` (lint, convert, backtest, vote, self-heal), `approve.py` and the web review page (human gate), `deploy_rule.py` (Kibana), `tools/ci_changes.py` and `scripts/ci_*.sh` (GitHub Actions), `tools/redeploy_all.py` (one-time reconciliation, dry run by default).
- A compliance layer: `docs/compliance/mapping.yml` and `objectives.yml` drive `tools/tag_compliance.py`, which writes tags and a "Defender notes" block (hardening, incident response, risk treatment) into each rule and generates `docs/compliance/COVERAGE.md`. CI fails on drift.
- A hunt tool and a FastAPI dashboard (`sf_hunt.py`, `sf_web.py`, `web/`) for IOC enrichment, rule review and engine status.
- About 2,100 offline tests, including event-level tests that replay hand-written events against every rule.

## Design decisions and the reason for each

- **Provenance gate fails closed.** A hunt verdict may trigger rule generation only if its provenance is valid, from a user or hunt source, with high trust. Missing or malformed provenance counts as unknown/low trust and is refused, and the engine's own records are never read back. Reason: two LLM-driven components that read each other's output can amplify a mistake, and the safe default for "cannot tell where this came from" is to do nothing. (`sf_safety.py`)
- **Validate before write for LLM output.** The model's Sigma is parsed with `yaml.safe_load`, checked against fixed limits and syntax rules, converted to a query, and re-rendered by the engine, which sets `id`, `author`, `date` and `status` itself. Failure reasons are fixed text that does not echo model output. Reason: model output is untrusted input; it was previously published as written. (`generate_rule.py`)
- **Point-in-time paging.** Event queries page with a PIT, `search_after` and a `_shard_doc` tiebreaker, and raise if a page is malformed or lacks a sort value, instead of returning a partial result as complete. If a PIT cannot be opened it falls back with a warning that completeness is not guaranteed. Reason: plain paging on a timestamp silently skips or repeats events that share a timestamp. (`lab/es.py`)
- **Advisory-lock state.** State files are written atomically under a kernel advisory lock, and read-modify-write goes through one lock hold (`lab.state.update`). A corrupt file is quarantined and raises. Reason: the engine, approval CLI, web app and scheduled jobs all touch the same JSON files, and an unlocked read-modify-write loses entries. A kernel lock is released when its holder dies, so there is no stale-lock logic. (`lab/state.py`)
- **Per-rule compliance notes.** The mapping is per technique, and `rules:` entries in `mapping.yml` override it for one rule id. Reason: two rules with the same technique can need different advice (for example `cmdkey` alone versus a scripted `cmdkey` or `mstsc` launch). (`tools/tag_compliance.py`)
- **Case-variant expansion.** Sigma matches case-insensitively, but the rendered Lucene query may not on keyword or wildcard fields. `lab.ecs` expands string literals on Windows case-insensitive fields into at most four variants, bounded to 200 clauses per query with stepwise degradation and a log warning, and `SF_CASE_VARIANTS=0` turns it off. Reason: Windows commands and paths appear in several casings, and the real index mapping could not be checked offline, so the conversion does not depend on it. (`lab/ecs.py`, `docs/ARCHITECTURE.md`)
- **Event-level rule tests.** Each rule is converted exactly as deployed and replayed against hand-written events: at least one that must match and one near-miss that must not. Reason: schema and conversion tests cannot tell a rule that fires from one that never can; this found rules that never could. (`tests/test_rule_events.py`, `tests/fixtures/events/`)
- **Retag-aware deploy.** An update changes only engine-owned fields, checks that the existing Kibana rule shares an ATT&CK technique with the new one, and requires `--allow-retag` to move to a different technique. Reason: a rule id collision or a mis-tag should not overwrite someone else's rule or an analyst's exceptions. (`deploy_rule.py`, `lab/kibana_rule.py`)

## Claim to evidence

| Claim | Evidence |
|---|---|
| Rule and technique counts in the README are computed, not typed | `tools/readme_tables.py --check`; `tests/test_readme_tables.py` |
| Every rule has a tag set and the COVERAGE file is in sync | `tools/tag_compliance.py --check`; `tests/test_compliance.py::test_every_shipped_rule_has_at_least_one_secplus_and_one_isc2cc_tag` |
| Tagged objective ids exist in the recorded outlines | `docs/compliance/objectives.yml`; `tests/test_compliance.py::test_mapping_ids_exist_in_reference_lists` |
| Per-rule overrides of defender notes work | `tests/test_compliance.py::test_rule_override_text_wins_and_other_text_kept` |
| Every rule can fire and has a near-miss that must not | `tests/test_rule_events.py::test_every_rule_has_a_positive_and_a_negative_event` |
| Deprecated rules do not count as coverage | `lab/coverage.py`; `tests/test_coverage.py::test_yaml_extension_is_scanned_and_deprecated_rules_are_not_coverage` |
| Queries match whatever the casing | `tests/test_ecs_case.py`; the `recased_*` fixtures in `tests/test_rule_events.py` |
| Missing provenance fails closed | `tests/test_provenance.py::test_missing_or_partial_provenance_fails_closed_as_low_trust`; `tests/test_safety.py` |
| Invalid LLM output is never published | `tests/test_generate_rule_validation.py`; `tests/test_generate_rule_hardening.py::test_gate_on_invalid_generation_is_not_queued_for_review` |
| A malformed vote is not an approval; quorum is two | `tests/test_validate_rule.py::test_passes_requires_quorum_of_valid_voters`, `::test_single_valid_voter_fails_quorum` |
| PIT paging returns each event once and fails loudly on bad pages | `tests/test_es_paging.py::test_duplicate_timestamps_exactly_once`, `::test_hit_without_sort_raises_search_error_and_closes_pit` |
| State is safe across processes | `tests/test_state_multiprocess.py`; `tests/test_state.py` |
| Deploy changes only engine-owned fields and guards lineage | `tests/test_deploy_rule.py::test_deploy_conflict_gets_then_patches_only_engine_owned_fields` |
| CI plans changed, removed and retagged rules; deploy needs validation to pass | `tests/test_ci_changes.py`; `tests/test_workflow.py::test_deploy_job_depends_on_validate_success` |
| Pull requests never reach the self-hosted runner or secrets | `tests/test_workflow.py::test_pull_requests_never_run_on_self_hosted`, `::test_no_secrets_exposed_to_pull_request_from_forks` |
| Admin routes are token-gated with lockout and a minimum length | `tests/test_web_security.py::test_repeated_wrong_tokens_lock_the_client_out_even_for_the_right_token`, `::test_token_shorter_than_16_disables_the_routes_with_a_clear_message` |
| Hunt is POST only and the host header is checked | `tests/test_web_security.py::test_hunt_is_post_only_and_get_is_405`, `::test_unknown_host_header_is_rejected` |
| TLS verification is on unless explicitly disabled | `lab/http.py`, `lab/config.py`; `tests/test_http.py`, `tests/test_config.py`; `tests/test_branding.py` (no `verify=False`) |
| Docs reference files and variables that exist | `tests/test_docs.py` |

## Review and fix history

The code was reviewed independently several times; the git log records each fix. Main findings:

- A run-ending recursion in the engine's state push (`_try_push_state`) and an Elasticsearch error that advanced `last_run`, so events were skipped. Both fixed with tests.
- Rules that could never fire: field and event-type combinations an event does not have, filters on missing fields. Found by writing the event-level tests; fixed in the rules.
- Rule logic that did not match its ATT&CK tag. These were retagged, split or deprecated. An early README stated 37 covered techniques; the corrected count is 28. The drop is the honest figure, not a regression.
- LLM-written rules were published as written. Now validated, normalised and written under safe file names; invalid output is queued as failed.
- Voting treated unclear model output as an approval; it now fails closed, requires a quorum, and keeps the original id and technique tags when healing.
- Redeploy overwrote analyst work in Kibana. It now reads, checks lineage, and patches only engine-owned fields; deprecated rules are disabled instead of created.
- CI could drop rules when runs were queued, ignored deletions and retags, and let one failing rule block healing of the others. The diff base, per-rule isolation and a scoped write token were added.
- Event search could truncate or repeat results; it now uses PIT paging and raises on partial pages.
- Concurrent writers could overwrite each other's state, and a corrupt file could be replaced by an empty one. Locking and quarantine were added.
- The web app lacked a host check, lockout and POST-only hunting, returned an empty list for corrupt state, and persisted web lookups. All changed.

## What is not verified, and what I would do next

Not verified:

- Anything against a live Elasticsearch, Kibana, GitHub Actions or LLM service. API shapes come from documentation and fixtures.
- The PIT and `_shard_doc` assumptions (version and privilege requirements), Kibana `PATCH` semantics, and the real field mapping behind the case-sensitivity question.
- Detection quality. There is no replayed attack telemetry and no true or false positive rate. Event fixtures are hand-written.
- The ISC2 CC, Security+, NIST and CIS mappings are the author's interpretation, not reviewed by the issuing bodies.

Next:

1. Stand up a small Elastic stack and run `docs/REDEPLOY.md` in dry-run mode, then the validate and deploy steps for one rule; fix what the live system shows.
2. Check the field mapping with the requests in `docs/ARCHITECTURE.md` and replace the case-variant assumption with the measured answer.
3. Replay Atomic Red Team tests against the lab and record per-rule results, to replace hand-written fixtures with captured events.
4. Put authentication on the read endpoints and make the review gate default on.
5. Add a hashed dependency lock file so CI can use `--require-hashes`.
6. Complete `.env.example` with the variables the code reads.
