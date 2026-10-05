# One-time bulk redeploy (`tools/redeploy_all.py`)

CI deploys only the rule files a push changed. Rules that were already deployed keep whatever
query Kibana got the first time, so after the case-variant query change, retags, deprecations and
new rules the deployed set is stale. This tool brings every deployed rule in line with
`detections/sigma` in one controlled pass.

## When to run it

After the rule/query changes are merged, and BEFORE you rely on the detections. Until it has run,
unchanged-but-regenerated rules still match with their old (case-sensitive) queries.

## Prerequisites

- `ELASTIC_URL`, `KIBANA_URL` and `ELASTIC_API_KEY` set (the tool refuses to run without
  `KIBANA_URL` and `ELASTIC_API_KEY`). The key needs read and write on Security / detection rules.
- The repo checked out at the commit you want deployed.
- Python environment of the repo (`./venv`), network access to Kibana.

## Commands

Dry run (default, reads only, no write requests are possible; the session is read-only):

    python tools/redeploy_all.py --report redeploy-plan.json

Review the plan, then apply (interactive confirmation on a terminal, or `--yes` in scripts):

    python tools/redeploy_all.py --apply --report redeploy-result.json
    python tools/redeploy_all.py --apply --yes --allow-retag <ID> <ID> --report redeploy-result.json

Options: `--rules-dir` (default `detections/sigma`), `--delay` seconds between writes (default
0.2), `--allow-retag ID ...`, `--report PATH`. `--apply` without `--yes` and without a terminal
exits 2. The plan is always computed in the same invocation as the apply.

Exit codes: 0 clean; 1 any ERROR, failed write, or RETAG-NEEDED not approved (a dry run exits 1
for the same findings, so it can gate a script); 2 usage, configuration or refused confirmation.

## What each action means

| Action | Meaning | `--apply` does |
|---|---|---|
| CREATE | rule id not in Kibana | creates it (enabled, as `deploy_rule.py` does) |
| UPDATE | exists, same technique lineage, an engine-owned field differs (summary shows query length old->new and the differing fields) | PATCHes engine-owned fields only |
| UNCHANGED | all engine-owned fields identical (list order ignored for tags, references, author, index) | nothing |
| DISABLE | `status: deprecated` and enabled in Kibana | disables it (never deletes) |
| NOOP-DEPRECATED | deprecated and absent or already disabled | nothing |
| RETAG-NEEDED | exists, but its technique tags share no lineage (T1016 and T1016.001 count as the same) with the shipped tags | nothing unless the id is in `--allow-retag`, then updates it |
| ERROR | conversion failure, HTTP error, unreadable file, missing id, mismatching rule_id | nothing; reported; the run continues |

Analyst-owned fields (`enabled`, `exceptions_list`, `actions`, `throttle`, `note`) are never sent on
update, by construction (the tool calls `deploy_rule.deploy_to_kibana`, which uses
`build_update_payload`). Note that an update goes through `deploy_to_kibana`'s normal flow: a
`POST` that Kibana answers with 409, then `GET`, then `PATCH`.

### Orphans

Reported only, never deleted. A rule in Kibana is listed as an orphan when its `rule_id` is a UUID
with no shipped file, it has an `attack.*` tag, and its author equals a shipped author. Delete a
confirmed orphan explicitly: `python deploy_rule.py --delete <rule_id>`. Rules that were split or
re-id'd show up here (the old id) and as CREATE (the new id).

## Handling RETAG-NEEDED

A retag means the shipped rule now claims a different technique than the one Kibana holds, which
is also what a rule-id collision looks like, so it is blocked by default. Check each one, then
pass only the ids you have reviewed to `--allow-retag`.

To see which shipped rules changed technique tags since the first tagged baseline (offline,
needs only git, no credentials):

    python tools/redeploy_all.py --suggest-retags [--since fde31e5] [--repo-dir .]

Output for this repo (fde31e5 -> HEAD), ids matched across commits:

| Rule id | Old tags | New tags | Needs `--allow-retag` |
|---|---|---|---|
| 1020dcc4-0817-41c0-ba1e-7d3034e816c6 | t1016 | t1016.001 | no (same lineage) |
| 831565f9-d936-4dcc-abaf-0112e0cb5bb4 | t1021.001, t1555.004 | t1021.001 | no (shared) |
| b8765da9-bc02-4c22-8b48-01096420d98a | t1614.001 | t1497.001 | yes |
| 5c8ea8be-7a0e-4809-b65a-2d26f91ee077 | t1218.011, t1546.011 | t1546.011 | no (shared) |
| 3f9a6b93-3242-4661-b8bc-e6871b802615 | t1046 | t1595 | yes |

The authoritative answer is the dry run, which compares against what Kibana actually holds. The
suggestion is only a guide: it compares git history, and Kibana may have been deployed from any
commit. The offline script step is equivalent to parsing each rule with `git show <rev>:<path>`
at `fde31e5` and at HEAD and comparing `attack.tNNNN[.NNN]` tags by rule id.

## Rollback

Kibana keeps no rule history here. A PATCH cannot be undone. To go back, check out the older commit
and redeploy those rule files (`deploy_rule.py <file>`, `--allow-retag` where tags move back).
Keep the dry-run JSON report: it records the old query length and differing fields per rule, not
the old query text, so for a real undo save a Kibana export first (Stack Management, Saved
Objects, export Security rules) before `--apply`.

## What could not be verified offline

The tool and its tests were run only against mocked HTTP. From memory of the Kibana docs and not
checked against a live instance:

- `GET /api/detection_engine/rules?rule_id=` returns 404 for an unknown rule and the rule JSON
  otherwise.
- `GET /api/detection_engine/rules/_find` pagination (`page`, `per_page`, `total`, `data`) and that
  it returns `author` and `tags` as lists.
- That Kibana returns the engine-owned fields in the same shape and defaults as they are sent
  (e.g. `from`, `interval`, `max_signals`, `index`). If it normalises any of them, every rule
  shows as UPDATE on the first dry run; check that before applying (a spurious UPDATE is harmless
  but noisy).
- That PATCH with only engine-owned fields leaves `enabled`, exceptions and actions untouched
  (documented behaviour, enforced here only by what the payload contains).
- Behaviour with Kibana spaces: only the default space is addressed.
