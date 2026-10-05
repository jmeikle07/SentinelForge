#!/usr/bin/env bash
# SentinelForge: scheduled rule-engine run WITH the review gate ON.
# Generates and validates rules, HOLDS them for human approval (approve.py),
# and emails the analyst. Never auto-deploys; approval is always a human step.
#
# Config comes from the environment / .env (see .env.example):
#   SF_LAB_DIR   project directory (default: directory containing this script)
#   SF_LOG_DIR   log directory      (default: $SF_LAB_DIR/logs)
#   ELASTIC_URL  Elasticsearch base URL
set -u

SF_LAB_DIR="${SF_LAB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
SF_LOG_DIR="${SF_LOG_DIR:-$SF_LAB_DIR/logs}"
mkdir -p "$SF_LOG_DIR"
LOG="$SF_LOG_DIR/sf_engine.log"

if [ -x "$SF_LAB_DIR/venv/bin/python" ]; then
  PY="$SF_LAB_DIR/venv/bin/python"
elif [ -x "$SF_LAB_DIR/venv/Scripts/python" ]; then
  PY="$SF_LAB_DIR/venv/Scripts/python"
else
  echo "venv python not found under $SF_LAB_DIR/venv" >> "$LOG"
  exit 1
fi

echo "===== $(date '+%Y-%m-%d %H:%M:%S') engine run (gated) =====" >> "$LOG"

cd "$SF_LAB_DIR" || { echo "cd failed" >> "$LOG"; exit 1; }

if [ -z "${ELASTIC_URL:-}" ] && [ -f .env ]; then
  ELASTIC_URL="$(grep -E '^ELASTIC_URL=' .env | head -n1 | cut -d= -f2- | tr -d '"'"'"'\r')"
fi
if [ -n "${ELASTIC_URL:-}" ] && command -v curl >/dev/null 2>&1; then
  if ! curl -s -o /dev/null --max-time 5 -k "$ELASTIC_URL"; then
    echo "Elasticsearch not reachable, skipping this run" >> "$LOG"
    exit 0
  fi
fi

# The gate flag is the whole point: validated rules are HELD, not deployed.
WATER_REVIEW_GATE=true "$PY" generate_rule.py >> "$LOG" 2>&1
echo "exit code: $?" >> "$LOG"
