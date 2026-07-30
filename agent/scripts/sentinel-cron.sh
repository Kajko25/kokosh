#!/usr/bin/env bash
# Wraps sentinel-run.mjs with jitter, a stand-down probability, and a hard daily action cap,
# so this doesn't look like — or become — a fixed-cadence bot loop. Meant to be installed
# as a cron job at a few-hours interval; the jitter/stand-down/cap below do the actual pacing.
set -euo pipefail
cd "$(dirname "$0")/../.."

# cron runs with a bare PATH that has no nvm shim, so a plain `node` is not found — the
# 2026-07-29 cycle died with exit 127 after reaching the scan. Resolved explicitly here, and the
# failure is loud rather than a "command not found" buried in a log nobody reads.
HEARTBEAT_EARLY="$(dirname "$0")/sentinel-heartbeat.sh"

if command -v node >/dev/null 2>&1; then
  NODE_BIN="$(command -v node)"
else
  # Newest installed nvm version, chosen by sort -V rather than glob order.
  NODE_BIN="$(ls -d "$HOME"/.nvm/versions/node/*/bin/node 2>/dev/null | sort -V | tail -1)"
fi
if [ -z "${NODE_BIN:-}" ] || [ ! -x "$NODE_BIN" ]; then
  echo "$(date -u -Iseconds) sentinel-run FAILED — no usable node binary (PATH=$PATH)"
  # The 2026-07-29 failure exactly. Publishing it is the point: this is the shape of outage the
  # heartbeat exists to surface, and it happens before any node code could report it.
  bash "$HEARTBEAT_EARLY" failed 127 0 || true
  exit 127
fi

HEARTBEAT="$(dirname "$0")/sentinel-heartbeat.sh"
# Publishes off-machine proof that this cycle ran. Called on every exit path, including the ones
# that do no work: a stand-down that publishes nothing is indistinguishable from a cron that
# never fired, which is the failure this whole mechanism exists to make visible.
heartbeat() { bash "$HEARTBEAT" "$@" || true; }

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
  heartbeat capped 0 0
  exit 0
fi

roll=$((RANDOM % 100))
if [ "$roll" -lt "$STAND_DOWN_PCT" ]; then
  echo "$(date -u -Iseconds) stand-down roll ($roll < $STAND_DOWN_PCT), skipping this cycle"
  heartbeat stand-down 0 0
  exit 0
fi

jitter=$((RANDOM % MAX_JITTER_SECONDS))
echo "$(date -u -Iseconds) sleeping ${jitter}s of jitter before running"
sleep "$jitter"
# Logged separately from the line above so a run killed mid-jitter (the WSL2 session
# ending, say) is distinguishable from one that reached the scan and then failed.
echo "$(date -u -Iseconds) jitter complete, starting scan"

# `set -e` plus command substitution would abort here on a non-zero exit *before* the
# captured output ever reached the log — which is exactly how a hard eth_getLogs failure
# stayed invisible for days, looking identical to a clean silent run. Capture the status.
set +e
output="$(cd agent && "$NODE_BIN" scripts/sentinel-run.mjs 2>&1)"
rc=$?
set -e
echo "$output"

if [ "$rc" -ne 0 ]; then
  echo "$(date -u -Iseconds) sentinel-run FAILED (exit $rc) — output above, state not advanced"
  heartbeat failed "$rc" 0
  exit "$rc"
fi
echo "$(date -u -Iseconds) run finished cleanly"

# `|| true` is load-bearing: with `set -e` and pipefail, grep finding nothing exits 1 and kills
# the script here — silently, before the heartbeat below ever runs. That is the same trap this
# file already documents around the scan itself, and it bit again three lines later.
found="$(printf '%s' "$output" | grep -oE '[0-9]+ new finding\(s\)' | grep -oE '^[0-9]+' | head -1 || true)"
if [ -n "$found" ]; then
  heartbeat findings 0 "$found"
else
  heartbeat clean 0 0
fi

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
