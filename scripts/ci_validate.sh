#!/usr/bin/env bash
# Validate (and self-heal) every changed rule. One failing rule never stops the others.
#
#   ci_validate.sh PLAN_DIR      (PLAN_DIR holds changed.z from tools/ci_changes.py)
#
# Writes passed.z / failed.z (NUL-delimited paths) into PLAN_DIR and always exits 0;
# the workflow fails the job in a later step, after the healed rules were committed.
# File names reach python only as "$file" arguments read from a NUL-delimited file.
set -u
plan=${1:?usage: ci_validate.sh PLAN_DIR}
py=${PYTHON:-python}
: > "$plan/passed.z"
: > "$plan/failed.z"
[ -f "$plan/changed.z" ] || exit 0
while IFS= read -r -d '' file; do
  echo "=========================================="
  echo "Validating: $file"
  echo "=========================================="
  if [ ! -f "$file" ]; then
    echo "::error::$file is in the diff but missing from the workspace"
    printf '%s\0' "$file" >> "$plan/failed.z"
    continue
  fi
  if "$py" validate_rule.py "$file" < /dev/null; then
    printf '%s\0' "$file" >> "$plan/passed.z"
  else
    echo "::error::CIRCUIT BREAKER: $file could not be validated or healed"
    printf '%s\0' "$file" >> "$plan/failed.z"
  fi
done < "$plan/changed.z"
exit 0
