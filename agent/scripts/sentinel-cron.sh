#!/usr/bin/env bash
# Wraps sentinel-run.mjs with jitter, a stand-down probability, and a hard daily action cap,
# so this doesn't look like — or become — a fixed-cadence bot loop. Meant to be installed
# as a cron job at a few-hours interval; the jitter/stand-down/cap below do the actual pacing.
set -euo pipefail
cd "$(dirname "$0")/../.."

STATE_DIR="docs"
ACTIONS_LOG="$STATE_DIR/sentinel-actions-today.json"
MAX_ACTIONS_PER_DAY="${MAX_ACTIONS_PER_DAY:-2}"
STAND_DOWN_PCT="${STAND_DOWN_PCT:-40}"   # skip this run entirely, this % of the time, before even scanning
MAX_JITTER_SECONDS="${MAX_JITTER_SECONDS:-2700}"  # up to 45 min

today="$(date -u +%Y-%m-%d)"
if [ -f "$ACTIONS_LOG" ]; then
  logged_day="$(python3 -c "import json;print(json.load(open('$ACTIONS_LOG')).get('day',''))" 2>/dev/null || echo "")"
  count="$(python3 -c "import json;print(json.load(open('$ACTIONS_LOG')).get('count',0))" 2>/dev/null || echo 0)"
else
  logged_day=""
  count=0
fi
if [ "$logged_day" != "$today" ]; then
  count=0
fi

if [ "$count" -ge "$MAX_ACTIONS_PER_DAY" ]; then
  echo "$(date -u -Iseconds) daily action cap ($MAX_ACTIONS_PER_DAY) already reached, skipping run"
  exit 0
fi

roll=$((RANDOM % 100))
if [ "$roll" -lt "$STAND_DOWN_PCT" ]; then
  echo "$(date -u -Iseconds) stand-down roll ($roll < $STAND_DOWN_PCT), skipping this cycle"
  exit 0
fi

jitter=$((RANDOM % MAX_JITTER_SECONDS))
echo "$(date -u -Iseconds) sleeping ${jitter}s of jitter before running"
sleep "$jitter"

output="$(cd agent && node scripts/sentinel-run.mjs 2>&1)"
echo "$output"

if echo "$output" | grep -q "finding(s):"; then
  python3 -c "
import json
path = '$ACTIONS_LOG'
try:
    d = json.load(open(path))
except Exception:
    d = {}
day = '$today'
count = d.get('count', 0) + 1 if d.get('day') == day else 1
json.dump({'day': day, 'count': count}, open(path, 'w'))
"
fi
