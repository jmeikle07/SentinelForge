# SentinelForge setup

Author: Jahsean Meikle

Step-by-step setup for running SentinelForge against your own Elastic stack. The offline test suite needs only steps 1 and 2. Everything else needs a reachable Elasticsearch and Kibana; none of that path has been verified against a live stack in this version, so expect to adjust on the first run.

## 1. Python environment

Python 3.11 or newer.

```bash
python -m venv venv
venv/bin/python -m pip install -r requirements-dev.txt   # Windows: venv\Scripts\python
```

## 2. Verify offline

```bash
venv/bin/python -m pytest
venv/bin/python tools/tag_compliance.py --check
venv/bin/python tools/readme_tables.py --check
```

## 3. Elastic prerequisites

- Elasticsearch and Kibana 8.x with the detection engine enabled.
- Sysmon events on Windows endpoints shipped by Elastic Agent. Rules are written against ECS field names (`process.command_line`, `process.parent.name`, ...); `lab/ecs.py` maps Sysmon-style fields to ECS during conversion.
- An API key for SentinelForge scoped as narrowly as you can: read on `logs-*` and `.alerts-security.alerts-*`, and Kibana privileges to manage detection rules. Create a new key; do not reuse any key from this repository's history (see "Key rotation" below).
- Serve Elasticsearch and Kibana over HTTPS with certificates your machine trusts. If the lab uses self-signed certificates, either add the CA to your trust store or set `LAB_INSECURE_TLS=1` (disables verification and logs a warning; lab use only).

## 4. Configuration

```bash
cp .env.example .env
```

`.env` is git-ignored. Python entry points load it with python-dotenv. Variables:

| Variable | Required | Used by | Notes |
|---|---|---|---|
| `ELASTIC_URL` | yes | everything that queries Elasticsearch | e.g. `https://elastic.example.internal:9200`. No default; a missing value raises `ConfigError`. |
| `ELASTIC_API_KEY` | yes | engine, validator, efficacy, deploy | Encoded API key. |
| `KIBANA_URL` | recommended | `deploy_rule.py`, ElastAlert dashboard link | If unset, derived from `ELASTIC_URL` with port 5601. |
| `LAB_INSECURE_TLS` | no | `lab.http`, ElastAlert | `1` disables TLS verification. Default off. |
| `ANTHROPIC_API_KEY` | for rule generation and voting | `generate_rule.py`, `validate_rule.py` | A missing key skips that voter with a warning. |
| `GEMINI_API_KEY` | for voting | `validate_rule.py` | Same behaviour. |
| `MODEL_NAME` | for Claude calls | `generate_rule.py`, `validate_rule.py` | Anthropic model identifier; read from the environment, not hardcoded. |
| `OLLAMA_URL`, `OLLAMA_MODEL` | no | `validate_rule.py` | Defaults to `http://localhost:11434` and a local model. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO` | for email reports | engine, validator circuit breaker | |
| `LAB_ADMIN_TOKEN` | to use approve/reject in the web UI | `sf_web.py` | Random string of **at least 16 characters** (generate one, below). Unset or shorter means the routes are disabled (403 with an explanatory message). Clients send it as `X-Admin-Token`. |
| `SF_ALLOWED_HOSTS` | no | `sf_web.py` | Comma-separated `Host` header allowlist (default `localhost,127.0.0.1,testserver`; `*.example.org` wildcards allowed). Requests with another Host get 400, which stops DNS-rebinding pages reading a localhost-bound server. Add your public hostname when serving behind a proxy. |
| `SF_AUTH_FAIL_LIMIT`, `SF_AUTH_FAIL_WINDOW` | no | `sf_web.py` | Wrong admin tokens per client before it is locked out of approve/reject (defaults 5 per 300 s; locked clients get 429 even with the right token until the window passes). |
| `WATER_REVIEW_GATE` | recommended `true` | `generate_rule.py` | Hold generated rules for human approval instead of deploying. Set by `run_engine.sh`. |
| `TARGET_HOST` | no | `generate_rule.py` | Restrict event queries to one `host.name`; `*` means all. |
| `SF_AUTHOR` | no | rule generation | Author written into generated rules. |
| `SF_REPO_URL` | no | review emails | Repository URL for the CI link; omitted when unset. |
| `SF_SELF_IPS` | no | `sf_hunt.py` | Comma-separated own IPs excluded from pivots. |
| `SF_HUNT_RATE_LIMIT`, `SF_HUNT_RATE_WINDOW` | no | `sf_web.py` | Hunt calls per window per client (defaults 10 per 60 s). |
| `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`, `ABUSECH_AUTH_KEY` | optional | `sf_hunt.py` | Each source degrades gracefully if its key is missing. |
| `SF_LAB_DIR`, `SF_LOG_DIR` | no | `run_*.sh`, `scripts/*` | Project directory and log directory; default to the script's location and `logs/`. |

`.env.example` lists the core variables; add the optional ones you need. Never commit `.env`.

## 5. Run the pieces

```bash
# Analyst IOC lookup
venv/bin/python sf_hunt.py 203.0.113.10            # or: scripts/sfhunt 203.0.113.10

# Dashboards and API. Generate a token of at least 16 characters; do not reuse a placeholder.
export LAB_ADMIN_TOKEN="$(venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))')"
venv/bin/python -m uvicorn sf_web:app --host 127.0.0.1 --port 8000
# open /, /engine, /review

# One gated engine run (generates, validates, holds for approval)
WATER_REVIEW_GATE=true venv/bin/python generate_rule.py      # or: scripts/sfengine

# Review held rules
venv/bin/python approve.py list
venv/bin/python approve.py show <rule_id>
venv/bin/python approve.py approve <rule_id>

# Efficacy
venv/bin/python rule_efficacy.py
```

Bind `sf_web` to localhost or put it behind an authenticating reverse proxy; do not expose it directly.

Web security notes:

- `/api/hunt` is a `POST` with a JSON body `{"ioc": "..."}`; the lookup value never appears in the URL, access logs or browser history. The web route keeps lookups in an in-memory cache only (never in `state/sf/hunt_memory.db`, which the CLI uses). Private, loopback, link-local and internal names are refused with HTTP 400 before any third-party call.
- Per-client limits (hunt rate, failed admin tokens) key on `request.client.host`. uvicorn runs with `--proxy-headers` **on by default** and then replaces that address with `X-Forwarded-For` from the addresses in `--forwarded-allow-ips` (default `127.0.0.1`). A proxy on the same machine must therefore overwrite `X-Forwarded-For` (nginx: `proxy_set_header X-Forwarded-For $remote_addr;`), otherwise a client can choose its own rate-limit identity. If your proxy cannot guarantee that, start uvicorn with `--no-proxy-headers` (all clients then share the proxy's address) and limit requests at the proxy as well.
- `sf_web` reads state files from `state/`. If one is corrupt the API answers 503 naming the file instead of showing an empty queue; the corrupt copy is kept as `<name>.corrupt` until you restore or delete it.

## 6. Compliance tagging workflow

After adding or editing a rule or `docs/compliance/mapping.yml`:

```bash
venv/bin/python tools/tag_compliance.py --write     # tags, defender notes, COVERAGE.md
venv/bin/python tools/readme_tables.py --write      # README tables
venv/bin/python tools/tag_compliance.py --check
```

Every technique used by a rule must exist in `mapping.yml`, and every objective ID in the mapping must exist in `docs/compliance/objectives.yml`. Existing rule `id` UUIDs must not change, because deployed Kibana rules key on them.

## 7. ElastAlert 2 (email on alerts)

The files in `elastalert/` are templates containing `${VAR}` placeholders. They are not valid ElastAlert configuration until rendered. `elastalert/run.sh` renders them with `envsubst` (from GNU gettext, which must be installed) into the git-ignored `elastalert/build/` directory and starts ElastAlert. Running `elastalert` directly on the templates will fail.

Required environment: `ELASTIC_URL`, `ELASTIC_API_KEY`, `ALERT_EMAIL_TO`, `ALERT_EMAIL_FROM`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_AUTH_FILE`. Optional: `ALERT_DASHBOARD_URL` (defaults to `KIBANA_URL`), `LAB_INSECURE_TLS`.

`SMTP_AUTH_FILE` points to a YAML file outside the repository (or at the git-ignored `elastalert/smtp_auth.yaml`) containing `user:` and `password:` keys. `chmod 600` it.

```bash
pip install elastalert2        # not in requirements.txt; install separately
export ELASTIC_URL=... ELASTIC_API_KEY=... ALERT_EMAIL_TO=... ALERT_EMAIL_FROM=... \
       SMTP_HOST=... SMTP_PORT=465 SMTP_AUTH_FILE=/secure/path/smtp_auth.yaml
elastalert/run.sh
```

## 8. GitHub Actions

`test.yml` needs no configuration: it runs `pytest` and `tag_compliance.py --check` on GitHub-hosted runners for pull requests and pushes, with read-only permissions and no secrets.

`deploy-detections.yml` runs on a **self-hosted** runner that can reach your Elasticsearch and Kibana, only for pushes to `main` that change `detections/sigma/**`. Configure under Settings, Secrets and variables, Actions:

| Kind | Name | Purpose |
|---|---|---|
| Secret | `ELASTIC_URL` | Elasticsearch URL |
| Secret | `KIBANA_URL` | Kibana URL |
| Secret | `ELASTIC_API_KEY` | API key for backtest and deploy |
| Secret | `ANTHROPIC_API_KEY` | Claude voter and self-heal |
| Secret | `GEMINI_API_KEY` | Gemini voter |
| Secret | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO` | Circuit-breaker email |
| Variable | `MODEL_NAME` | Anthropic model identifier |

Ollama is expected on the runner at `OLLAMA_URL` (default `http://localhost:11434`). Do not enable the deploy workflow for pull requests from forks; a self-hosted runner would execute untrusted code on your lab network.

How the deploy workflow behaves (logic in `tools/ci_changes.py` and `scripts/ci_*.sh`; the runner needs bash and git 2.31 or newer):

- **Changed, removed, retagged.** Each run diffs a base commit against the pushed commit. Added, modified and renamed (new path) rules are validated and deployed. A deleted rule, or a renamed or edited rule whose id changed, is retired from Kibana with `deploy_rule.py --delete <id>`, but only if no file in the new tree still carries that id (a pure rename keeps its id and is never deleted). Deprecated rules are never deleted; deploy disables them. A rule whose `attack.tNNNN[.NNN]` tags differ from its previous version is deployed with `--allow-retag`; new rules and edits that keep their techniques never get that flag.
- **Diff base and queueing.** Runs queue (`cancel-in-progress: false`). GitHub keeps only one pending run per concurrency group, so a rapid third push replaces the pending second run. To avoid skipping its rules, the base is the head of the newest successful run of this workflow (looked up with the Actions API, which is why the validate job has `actions: read`), falling back to the push's `before` sha, then to the parent commit. Consequence: a push whose run failed is diffed again by the next run, so a broken rule keeps the run red (and blocks deploying the other rules of that range, because deploy gating is strict) until it is fixed or removed. Limits: the lookup needs API access; if it fails the fallback is the per-push range.
- **One bad rule does not discard the others' healing.** Every changed rule is validated. Rules that passed are tagged (`tag_compliance.py --write --files`, skipped with a log line when the technique is unmapped), committed with `[skip ci]` and pushed; then the job fails if any rule failed, and the deploy job does not run. The heal commit cannot retrigger the workflow (`[skip ci]`, and pushes with `GITHUB_TOKEN` never start runs).
- **Credentials.** The validate job checks out with `persist-credentials: false`; the token is passed only to the plan step (read-only API call) and to the push step, through `GIT_CONFIG_*` environment variables (nothing in `.git/config`, URLs or argv). `contents: write` exists solely for that push. `pip install` uses the pinned `requirements.txt`; `--require-hashes` is not used because the repo has no fully hashed lock file (that would also need every transitive dependency).
- **Branch protection.** If `main` is protected, the heal push (and the rebase before it) can fail after validation succeeded. The run is then red and the healed rules are not published. Allow `github-actions[bot]` to bypass the protection, or change the workflow to push with a PAT secret.
- **Pull request checks.** `test.yml` runs `tag_compliance.py --check --allow-untagged` (new autogenerated rules are untagged until the heal commit tags them) and `readme_tables.py --check`.

## 9. Scheduling with launchd (macOS, optional)

`run_efficacy.sh` refreshes `state/rule_efficacy.json` and `run_engine.sh` performs a gated engine run. Both resolve the project directory from `SF_LAB_DIR` or their own location, use `venv/bin/python`, read `ELASTIC_URL` from the environment or `.env`, skip quietly if Elasticsearch is unreachable, and log to `logs/`. The plist files in `scheduler/` contain a `__SF_LAB_DIR__` placeholder; substitute it when installing:

```bash
export SF_LAB_DIR="$(pwd)"
mkdir -p "$SF_LAB_DIR/logs" ~/Library/LaunchAgents
for job in efficacy engine; do
  sed "s|__SF_LAB_DIR__|$SF_LAB_DIR|g" "scheduler/com.sf.$job.plist" > ~/Library/LaunchAgents/com.sf.$job.plist
  launchctl load ~/Library/LaunchAgents/com.sf.$job.plist
done
# remove: launchctl unload ~/Library/LaunchAgents/com.sf.<job>.plist
```

`com.sf.efficacy` runs every 15 minutes; `com.sf.engine` runs at 08:00 and 20:00. launchd does not read `.env`, which is why the scripts load `ELASTIC_URL` from it themselves and the Python programs call python-dotenv. If you use a VPN to reach Elastic, bring it up before the job runs; the scripts no longer manage it.

## 10. Key rotation (action required)

An Elastic API key was committed to this repository's earlier history (in the ElastAlert configuration). Removing it from the current files does not remove it from clones, forks, caches or earlier commits. Treat it as compromised:

1. In Kibana, Stack Management, API keys: invalidate the old key.
2. Create a new, narrowly scoped key and store it only in `.env` and the `ELASTIC_API_KEY` Actions secret.
3. If the repository was ever public, also rotate any other credential that appeared in earlier commits (SMTP passwords, demo-account passwords, third-party API keys) and consider rewriting history with a tool such as `git filter-repo`, understanding that this does not retract copies already taken.

## State files

`state/*.json` are runtime data written by the programs through `lab.state`. The committed copies are example snapshots; they can be deleted and will be regenerated. A corrupt file is renamed to `<name>.corrupt` (git-ignored) and the program raises an error rather than overwriting it.
