#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage:
  scripts/safe-squash.sh --from <base-commit> --message "<commit message>" [--apply] [--push]

Behavior:
  - Default is DRY RUN (no history rewrite).
  - Creates local safety branch: rescue/safe-squash-<timestamp>
  - Verifies file-count parity before and after squash.
  - With --apply: rewrites current branch to one squashed commit.
  - With --push: force-pushes with lease after apply.
USAGE
}

BASE=""
MSG=""
APPLY=0
PUSH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) BASE="${2:-}"; shift 2 ;;
    --message) MSG="${2:-}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --push) PUSH=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$BASE" || -z "$MSG" ]]; then
  usage
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: working tree is not clean. Commit/stash first." >&2
  exit 1
fi

if ! git merge-base --is-ancestor "$BASE" HEAD; then
  echo "ERROR: --from commit is not an ancestor of HEAD." >&2
  exit 1
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
HEAD_SHA="$(git rev-parse --short HEAD)"
TS="$(date +%Y%m%d-%H%M%S)"
RESCUE_BRANCH="rescue/safe-squash-$TS"
TMP_BRANCH="tmp/safe-squash-$TS"
BEFORE_MANIFEST="$(mktemp)"
AFTER_MANIFEST="$(mktemp)"
DIFF_FILE="$(mktemp)"

cleanup() {
  rm -f "$BEFORE_MANIFEST" "$AFTER_MANIFEST" "$DIFF_FILE"
}

trap cleanup EXIT

git ls-tree -r --name-only HEAD | sort > "$BEFORE_MANIFEST"
FILECOUNT_BEFORE="$(wc -l < "$BEFORE_MANIFEST" | tr -d ' ')"
COMMITS_TO_SQUASH="$(git rev-list --count "$BASE"..HEAD)"

echo "Branch: $CURRENT_BRANCH"
echo "HEAD: $HEAD_SHA"
echo "Base: $BASE"
echo "Commits to squash: $COMMITS_TO_SQUASH"
echo "File count before: $FILECOUNT_BEFORE"
echo "Rescue branch: $RESCUE_BRANCH"

if [[ "$APPLY" -eq 0 ]]; then
  echo "DRY RUN complete. Re-run with --apply to execute."
  exit 0
fi

git branch "$RESCUE_BRANCH" HEAD

git checkout -b "$TMP_BRANCH" "$BASE" >/dev/null 2>&1
git merge --squash "$CURRENT_BRANCH" >/dev/null 2>&1
git commit -m "$MSG" >/dev/null 2>&1

git ls-tree -r --name-only HEAD | sort > "$AFTER_MANIFEST"
FILECOUNT_AFTER="$(wc -l < "$AFTER_MANIFEST" | tr -d ' ')"
echo "File count after: $FILECOUNT_AFTER"

if ! diff -u "$BEFORE_MANIFEST" "$AFTER_MANIFEST" > "$DIFF_FILE"; then
  echo "ERROR: tracked file manifest changed during squash." >&2
  cat "$DIFF_FILE" >&2
  echo "Keeping rescue branch: $RESCUE_BRANCH" >&2
  git checkout "$CURRENT_BRANCH" >/dev/null 2>&1
  exit 1
fi

NEW_SHA="$(git rev-parse --short HEAD)"

git checkout "$CURRENT_BRANCH" >/dev/null 2>&1
git reset --hard "$TMP_BRANCH" >/dev/null 2>&1
git branch -D "$TMP_BRANCH" >/dev/null 2>&1

echo "Squash applied on $CURRENT_BRANCH -> $NEW_SHA"
echo "Rescue branch available: $RESCUE_BRANCH"

if [[ "$PUSH" -eq 1 ]]; then
  git push --force-with-lease origin "$CURRENT_BRANCH"
  echo "Pushed with --force-with-lease"
fi
