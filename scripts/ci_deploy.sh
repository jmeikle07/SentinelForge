#!/usr/bin/env bash
# Deploy the validated rules to Kibana and retire removed ones.
#
#   ci_deploy.sh PLAN_DIR        (deploy.z and removed.z from tools/ci_changes.py)
#
# deploy.z holds alternating "deploy"|"retag" and path; "retag" adds --allow-retag (the rule id
# already exists and its ATT&CK technique tags changed). removed.z holds rule ids for --delete.
# Everything is read NUL-delimited and passed as separate arguments; nothing is eval'd.
# Keeps going after a failure and exits 1 at the end if any step failed.
set -u
plan=${1:?usage: ci_deploy.sh PLAN_DIR}
py=${PYTHON:-python}
failed=0

if [ -f "$plan/deploy.z" ]; then
  while IFS= read -r -d '' mode && IFS= read -r -d '' file; do
    if [ ! -f "$file" ]; then
      echo "::error::$file is in the diff but missing from the workspace"
      failed=1
      continue
    fi
    echo "Deploying: $file ($mode)"
    if [ "$mode" = "retag" ]; then
      "$py" deploy_rule.py "$file" --allow-retag < /dev/null || failed=1
    else
      "$py" deploy_rule.py "$file" < /dev/null || failed=1
    fi
  done < "$plan/deploy.z"
fi

if [ -f "$plan/removed.z" ]; then
  while IFS= read -r -d '' rid; do
    echo "Retiring removed rule: $rid"
    "$py" deploy_rule.py --delete "$rid" < /dev/null || failed=1
  done < "$plan/removed.z"
fi
exit "$failed"
