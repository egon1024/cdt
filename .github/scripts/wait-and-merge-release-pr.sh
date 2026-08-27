#!/usr/bin/env bash
# Wait for required CI checks on a release bump PR, then merge it.
set -euo pipefail

pr_number="${1:?PR number is required}"
max_wait_seconds="${MAX_WAIT_SECONDS:-1800}"
checks_appear_wait_seconds="${CHECKS_APPEAR_WAIT_SECONDS:-300}"
checks_poll_interval="${CHECKS_POLL_INTERVAL:-10}"

wait_for_checks_to_start() {
  local elapsed=0
  while true; do
    local output=""
    if output="$(gh pr checks "${pr_number}" 2>&1)"; then
      if ! grep -qi "no checks reported" <<<"${output}"; then
        echo "CI checks reported on PR #${pr_number}:"
        echo "${output}"
        return 0
      fi
    elif ! grep -qi "no checks reported" <<<"${output}"; then
      echo "${output}"
      return 0
    fi

    if (( elapsed >= checks_appear_wait_seconds )); then
      echo "::error::No CI checks appeared on PR #${pr_number} within ${checks_appear_wait_seconds}s"
      return 1
    fi

    echo "Waiting for CI checks to start on PR #${pr_number} (${elapsed}s)..."
    sleep "${checks_poll_interval}"
    elapsed=$((elapsed + checks_poll_interval))
  done
}

echo "Waiting for CI checks to appear on PR #${pr_number}..."
if ! wait_for_checks_to_start; then
  gh pr checks "${pr_number}" || true
  exit 1
fi

echo "Waiting for required checks on PR #${pr_number} (up to ${max_wait_seconds}s)..."
if ! timeout "${max_wait_seconds}" gh pr checks "${pr_number}" --watch --fail-fast --interval 15; then
  echo "::error::Required checks did not pass on PR #${pr_number} within ${max_wait_seconds}s"
  gh pr checks "${pr_number}" || true
  exit 1
fi

echo "Merging PR #${pr_number}..."
gh pr merge "${pr_number}" --rebase --admin --delete-branch
