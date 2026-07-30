#!/usr/bin/env bash
# Publish proof that a sentinel cycle happened, somewhere off this machine.
#
# The problem this solves: the sentinel's cron died on 2026-07-29 (`node: command not found`)
# and nobody noticed for a day, because a dead cron and a healthy stand-down produce identical
# silence. /sentinel exposed that gap to the outside — but only for state baked into the
# deployed bundle, which a local cron run does not touch. So from anywhere but this laptop,
# "did the cron fire?" was unanswerable.
#
# Each cycle now writes one small JSON to the `sentinel-heartbeat` branch. Absence becomes
# visible: a stale `publishedAt` means no cycle completed, whatever the reason.
#
# Built with git plumbing — hash-object, mktree, commit-tree — so it never touches the working
# tree, the index, or HEAD. That matters because this runs unattended from cron and may fire
# while someone is mid-edit on main; a script that ran `git add`/`git checkout` could commit
# unrelated work-in-progress or stomp a rebase. Nothing here can: it builds an object graph
# directly and pushes it.
#
# Usage: sentinel-heartbeat.sh <outcome> [exit-code] [findings-count]
#   outcome: stand-down | capped | clean | findings | failed | killed
#
# Failure to publish is reported but never fatal — the heartbeat is observability, and losing it
# must not turn a healthy scan into a failed cycle.

set -uo pipefail
cd "$(dirname "$0")/../.."

# git's credential helper for github.com is `!gh auth git-credential`, and cron's PATH has no
# more idea where `gh` lives than it did about `node`. Without this the push fails with
# "could not read Username", which looks like an auth problem rather than a PATH one. Caught by
# testing under `env -i PATH=/usr/bin:/bin`; the real cron would have hit it on the first cycle.
for candidate in "$HOME/.local/bin" "/usr/local/bin"; do
  if [ -x "$candidate/gh" ] && ! command -v gh >/dev/null 2>&1; then
    PATH="$candidate:$PATH"
    export PATH
  fi
done

BRANCH="${HEARTBEAT_BRANCH:-sentinel-heartbeat}"
FILE="sentinel-heartbeat.json"
STATE="agent/data/sentinel-state.json"

outcome="${1:-unknown}"
exit_code="${2:-0}"
findings="${3:-0}"

payload="$(
  STATE_PATH="$STATE" OUTCOME="$outcome" EXIT_CODE="$exit_code" FINDINGS="$findings" \
  CODE_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
  python3 - <<'PY'
import json, os, socket, datetime

state = {}
try:
    with open(os.environ["STATE_PATH"]) as fh:
        state = json.load(fh)
except Exception:
    pass  # a missing or corrupt state file is itself worth publishing, as nulls

print(json.dumps({
    "publishedAt": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "outcome": os.environ["OUTCOME"],
    "exitCode": int(os.environ["EXIT_CODE"]),
    "newFindings": int(os.environ["FINDINGS"]),
    # What the scan itself recorded. Null when the cycle never got far enough to write state,
    # which is exactly the case worth telling apart from a clean run.
    "lastRunAt": state.get("lastRunAt"),
    "lastScannedBlock": state.get("lastScannedBlock"),
    "knownFlaggedTokens": len(state.get("knownFlaggedTokens") or []) or None,
    "detectorFingerprint": state.get("detectorFingerprint"),
    # Which commit's code produced this, so a heartbeat from a stale checkout is identifiable.
    "codeCommit": os.environ["CODE_COMMIT"],
    "host": socket.gethostname(),
}, indent=2))
PY
)"

if [ -z "$payload" ]; then
  echo "$(date -u -Iseconds) heartbeat SKIPPED — could not build payload"
  exit 0
fi

publish() {
  local blob tree parent commit
  blob="$(printf '%s\n' "$payload" | git hash-object -w --stdin)" || return 1
  tree="$(printf '100644 blob %s\t%s\n' "$blob" "$FILE" | git mktree)" || return 1

  # Chain onto whatever is already published, so the branch keeps a history of cycles rather
  # than a single rewritten commit. Fetched fresh: this machine never checks the branch out, so
  # a local ref would drift from the remote without anyone noticing.
  git fetch --quiet origin "$BRANCH" 2>/dev/null
  parent="$(git rev-parse --verify --quiet FETCH_HEAD)"

  if [ -n "$parent" ]; then
    commit="$(git commit-tree "$tree" -p "$parent" -m "sentinel heartbeat: $outcome")" || return 1
  else
    commit="$(git commit-tree "$tree" -m "sentinel heartbeat: $outcome")" || return 1
  fi

  git push --quiet origin "$commit:refs/heads/$BRANCH"
}

if publish; then
  echo "$(date -u -Iseconds) heartbeat published to $BRANCH ($outcome)"
else
  # Non-fatal on purpose. A push failure (offline laptop, expired credential) says nothing about
  # whether the scan worked, and must not be reported as if it did.
  echo "$(date -u -Iseconds) heartbeat publish FAILED — scan result above is unaffected"
fi
exit 0
