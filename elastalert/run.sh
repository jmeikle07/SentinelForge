#!/usr/bin/env bash
# Render the ElastAlert templates from environment variables and start ElastAlert 2.
# Required env: ELASTIC_URL, ELASTIC_API_KEY, SMTP_HOST, SMTP_PORT, ALERT_EMAIL_TO,
#               ALERT_EMAIL_FROM, SMTP_AUTH_FILE. Optional: ALERT_DASHBOARD_URL, LAB_INSECURE_TLS.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/build"
VARS='${ELASTIC_HOST} ${ELASTIC_PORT} ${ELASTIC_API_KEY} ${ELASTALERT_RULES_DIR} ${ALERT_EMAIL_TO} ${ALERT_EMAIL_FROM} ${SMTP_HOST} ${SMTP_PORT} ${SMTP_AUTH_FILE} ${ALERT_DASHBOARD_URL}'

: "${ELASTIC_URL:?ELASTIC_URL is required}"
: "${ELASTIC_API_KEY:?ELASTIC_API_KEY is required}"
for v in ALERT_EMAIL_TO ALERT_EMAIL_FROM SMTP_HOST SMTP_PORT SMTP_AUTH_FILE; do
  : "${!v:?$v is required}"
done

hostport="${ELASTIC_URL#*://}"; hostport="${hostport%%/*}"
export ELASTIC_HOST="${hostport%%:*}"
if [ "${hostport##*:}" = "$hostport" ]; then export ELASTIC_PORT=9200; else export ELASTIC_PORT="${hostport##*:}"; fi
export ELASTALERT_RULES_DIR="$OUT/rules"
export ALERT_DASHBOARD_URL="${ALERT_DASHBOARD_URL:-${KIBANA_URL:-}}"

umask 077
mkdir -p "$OUT/rules"
envsubst "$VARS" < "$HERE/config.yaml" > "$OUT/config.yaml"
for f in "$HERE"/rules/*.yaml; do
  envsubst "$VARS" < "$f" > "$OUT/rules/$(basename "$f")"
done
if [ "${LAB_INSECURE_TLS:-0}" = "1" ]; then
  echo "WARNING: LAB_INSECURE_TLS=1, ElastAlert TLS verification disabled" >&2
  sed -i.bak 's/^verify_certs: true/verify_certs: false/' "$OUT/config.yaml" && rm -f "$OUT/config.yaml.bak"
fi
exec elastalert --config "$OUT/config.yaml" --verbose
