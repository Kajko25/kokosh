#!/usr/bin/env bash
# Push the files the sentinel writes to the branch the agent is deployed from.
#
# The problem this solves: the cron writes `agent/data/sentinel-state.json` on this laptop, but
# /exposure and /sentinel read it out of the deployed bundle, which comes from `main`. So a clean
# cycle updated the state locally and the deployed agent went on reporting the previous run --
# `overdue: true`, `stale: true` -- until somebody remembered to commit. On 2026-08-02 that gap
# was three days wide, and nothing about it was visible from outside: the scan had worked, the
# heartbeat said `clean`, and the agent still served July data.
#
# Built with git plumbing -- hash-object, read-tree into a throwaway index, write-tree,
# commit-tree -- for the same reason `sentinel-heartbeat.sh` is: this runs unattended and may
# fire while someone is mid-edit or mid-rebase on `main`. `git add` + `git commit` there would
# sweep unrelated work in progress into an automated commit. Nothing here can touch the working
# tree, the real index, or HEAD.
#
# The base tree comes from the freshly fetched remote branch, and only the paths named below are
# replaced in it. That is the load-bearing property: whatever else is dirty locally -- a
# half-finished lib/, an experimental script -- is structurally incapable of reaching the commit,
# because it was never read.
#
# Usage: publish-state.sh [path ...]   (default: the sentinel's state and approval snapshot)
#
# Publishing failure is loud but never fatal. A rejected push says nothing about whether the scan
# worked, and turning a healthy cycle into a failed one would be a worse outcome than stale data.

set -uo pipefail
cd "$(dirname "$0")/../.."

# Same PATH problem, same fix as the heartbeat: git's credential helper for github.com is
# `!gh auth git-credential`, and cron's PATH does not have `gh` on it.
for candidate in "$HOME/.local/bin" "/usr/local/bin"; do
  if [ -x "$candidate/gh" ] && ! command -v gh >/dev/null 2>&1; then
    PATH="$candidate:$PATH"
    export PATH
  fi
done

BRANCH="${STATE_BRANCH:-main}"
REMOTE="${STATE_REMOTE:-origin}"

if [ "$#" -gt 0 ]; then
  PATHS=("$@")
else
  PATHS=("agent/data/sentinel-state.json" "agent/data/approvals-report.json")
fi

log() { echo "$(date -u -Iseconds) $*"; }

tmpindex="$(mktemp -t kokosh-state-index.XXXXXX)"
rm -f "$tmpindex"   # git wants to create it itself; mktemp only reserves the name
cleanup() { rm -f "$tmpindex"; }
trap cleanup EXIT

publish() {
  local parent base_tree tree commit blob mode present=0

  # Fetched fresh every time. This machine works on `main` directly, so a local ref can sit
  # behind the remote; committing onto a stale parent would produce a push that is either
  # rejected or, worse, reverts whatever landed in between.
  git fetch --quiet "$REMOTE" "$BRANCH" || { log "state publish FAILED -- could not fetch $REMOTE/$BRANCH"; return 1; }
  parent="$(git rev-parse --verify --quiet FETCH_HEAD)" || true
  if [ -z "$parent" ]; then
    log "state publish FAILED -- $REMOTE/$BRANCH has no commit to build on"
    return 1
  fi

  base_tree="$(git rev-parse --verify --quiet "$parent^{tree}")" || return 1
  GIT_INDEX_FILE="$tmpindex" git read-tree "$base_tree" || return 1

  for path in "${PATHS[@]}"; do
    if [ ! -f "$path" ]; then
      # Not an error: the approval snapshot is produced by a separate manual scan and may
      # legitimately not exist on a machine that has only ever run the sentinel.
      log "state publish -- skipping $path (not present locally)"
      continue
    fi
    present=1
    blob="$(git hash-object -w -- "$path")" || return 1
    # Preserve the executable bit if the file somehow has one; state files are 100644.
    if [ -x "$path" ]; then mode=100755; else mode=100644; fi
    GIT_INDEX_FILE="$tmpindex" git update-index --add --cacheinfo "$mode,$blob,$path" || return 1
  done

  if [ "$present" -eq 0 ]; then
    log "state publish -- nothing to publish, no named path exists locally"
    return 0
  fi

  tree="$(GIT_INDEX_FILE="$tmpindex" git write-tree)" || return 1

  # The whole point of comparing trees rather than diffing files: a cycle that scanned new blocks
  # but found nothing still rewrites `lastRunAt`, so "did anything change" cannot be answered by
  # asking whether the run did work. If the tree is identical, there is nothing to say.
  if [ "$tree" = "$base_tree" ]; then
    log "state publish -- already current on $REMOTE/$BRANCH, nothing to do"
    return 0
  fi

  commit="$(git commit-tree "$tree" -p "$parent" -m "sentinel: publish state after a clean cycle")" || return 1

  # No --force, deliberately. The parent is the remote tip as of a moment ago; if someone pushed
  # in between, this is no longer a fast-forward and git refuses. Retrying next cycle is correct
  # -- overwriting a human's commit with an automated state bump is not.
  if git push --quiet "$REMOTE" "$commit:refs/heads/$BRANCH"; then
    log "state publish -- pushed ${commit:0:12} to $REMOTE/$BRANCH"
    return 0
  fi

  log "state publish FAILED -- push rejected (branch moved, or no credentials); state is committed nowhere"
  return 1
}

if publish; then
  exit 0
fi
# Non-fatal on purpose: see the header. The caller's scan result stands regardless.
exit 0
