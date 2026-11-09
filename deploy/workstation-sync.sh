#!/usr/bin/env bash
# Workstation side of GMshield CI/CD. The pipeline itself runs on roberto-server; this only:
#  1. copies CI/CD reports from roberto-server into docs/artifacts (additive, never deletes), and
#  2. fast-forwards the local develop and main of each GMshield clone to match GitHub.
#     Local work is never touched: a branch with unpushed commits, or a checked-out branch with
#     uncommitted changes, is left as is and reported.
set -uo pipefail
ROOT=${GMSHIELD_ROOT:-$HOME/agentic-RPG}
DEST=${GMSHIELD_ARTIFACTS:-$ROOT/docs/artifacts}

mkdir -p "$DEST"
rsync -a --timeout=60 -e "ssh -o ClearAllForwardings=yes -o BatchMode=yes -o ConnectTimeout=10" \
  roberto-server:gmshield-ci/artifacts/ "$DEST/" || echo "artifacts: copy failed (rsync exit $?); will retry"

for repo in "$ROOT"/GMshield-*/; do
  name=$(basename "$repo")
  [ -d "$repo/.git" ] || continue
  git -C "$repo" remote get-url origin >/dev/null 2>&1 || continue
  git -C "$repo" fetch --quiet --prune origin || { echo "$name: fetch failed"; continue; }
  current=$(git -C "$repo" symbolic-ref --quiet --short HEAD || true)
  for b in develop main; do
    git -C "$repo" rev-parse --verify -q "refs/remotes/origin/$b" >/dev/null || continue
    if ! git -C "$repo" rev-parse --verify -q "refs/heads/$b" >/dev/null; then
      git -C "$repo" branch --quiet --track "$b" "origin/$b"
      continue
    fi
    [ "$(git -C "$repo" rev-parse "$b")" = "$(git -C "$repo" rev-parse "origin/$b")" ] && continue
    if ! git -C "$repo" merge-base --is-ancestor "$b" "origin/$b"; then
      echo "$name/$b: has local commits not on GitHub; left untouched"
    elif [ "$b" != "$current" ]; then
      git -C "$repo" fetch --quiet origin "$b:$b"          # refuses anything but a fast-forward
    elif [ -z "$(git -C "$repo" status --porcelain)" ]; then
      git -C "$repo" merge --quiet --ff-only "origin/$b"
    else
      echo "$name/$b: checked out with uncommitted changes; left untouched"
    fi
  done
done
