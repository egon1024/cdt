#!/usr/bin/env bash
# Wait for required CI checks on a release bump PR, then merge it.
set -euo pipefail

pr_number="${1:?PR number is required}"
max_wait_seconds="${MAX_WAIT_SECONDS:-1800}"

echo "Waiting for required checks on PR #${pr_number} (up to ${max_wait_seconds}s)..."
if ! timeout "${max_wait_seconds}" gh pr checks "${pr_number}" --watch --fail-fast --interval 15; then
  echo "::error::Required checks did not pass on PR #${pr_number} within ${max_wait_seconds}s"
  gh pr checks "${pr_number}" || true
  exit 1
fi

echo "Merging PR #${pr_number}..."
gh pr merge "${pr_number}" --rebase --admin --delete-branch
