#!/usr/bin/env bash
# Resolve the merged PR description for a release bump.
set -euo pipefail

GITHUB_REPOSITORY="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
GITHUB_SHA="${GITHUB_SHA:?GITHUB_SHA is required}"
COMMIT_MESSAGE="${1:-}"

write_body_output() {
  local body="$1"
  {
    echo "body<<EOF"
    echo "$body"
    echo "EOF"
  } >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"
}

fetch_body_by_sha() {
  local result=""
  if result="$(gh api "repos/${GITHUB_REPOSITORY}/commits/${GITHUB_SHA}/pulls" \
    --jq '.[0].body // empty' 2>/dev/null)"; then
    echo "$result"
  fi
}

fetch_body_by_number() {
  local pr_number="$1"
  local result=""
  if result="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${pr_number}" \
    --jq '.body // empty' 2>/dev/null)"; then
    echo "$result"
  fi
}

parse_pr_number() {
  local message="$1"
  if [[ "$message" =~ Merge[[:space:]]pull[[:space:]]request[[:space:]]\#([0-9]+) ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$message" =~ \ \#([0-9]+)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

body=""
pr_number=""
if [[ -n "$COMMIT_MESSAGE" ]]; then
  pr_number="$(parse_pr_number "$COMMIT_MESSAGE" || true)"
fi

for attempt in 1 2 3 4 5 6; do
  body="$(fetch_body_by_sha)"
  if [[ -z "$body" && -n "$pr_number" ]]; then
    body="$(fetch_body_by_number "$pr_number")"
    if [[ -n "$body" ]]; then
      echo "Resolved PR body via PR #${pr_number} (attempt ${attempt})."
      write_body_output "$body"
      exit 0
    fi
  elif [[ -n "$body" ]]; then
    echo "Resolved PR body via commit SHA (attempt ${attempt})."
    write_body_output "$body"
    exit 0
  fi

  if ((attempt < 6)); then
    delay=$((attempt * 2))
    echo "No PR linked to ${GITHUB_SHA} yet; retrying in ${delay}s (attempt ${attempt}/6)..."
    sleep "$delay"
  fi
done

echo "::error::No pull request found for merge commit ${GITHUB_SHA}. Releases require a merged PR."
exit 1
