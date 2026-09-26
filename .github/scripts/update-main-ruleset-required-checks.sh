#!/usr/bin/env bash
# Update the "main" repository ruleset required status checks after CI job renames.
# Run locally as a repo admin:  bash .github/scripts/update-main-ruleset-required-checks.sh
set -euo pipefail

REPO="${REPO:-egon1024/cdt}"
RULESET_ID="${RULESET_ID:-21221480}"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

gh api "repos/${REPO}/rulesets/${RULESET_ID}" >"$tmp"

jq '
  .rules |= map(
    if .type == "required_status_checks" then
      .parameters.required_status_checks = [
        {"context": "Format, Clippy, Test (amd64)", "integration_id": 15368},
        {"context": "Format, Clippy, Test (arm64)", "integration_id": 15368},
        {"context": "Preview next release version", "integration_id": 15368}
      ]
    else .
    end
  )
  | del(.id, .source, .source_type, .node_id, .created_at, .updated_at, .current_user_can_bypass, ._links)
' "$tmp" >"${tmp}.put"

echo "Required checks will be:"
jq -r '.rules[] | select(.type=="required_status_checks") | .parameters.required_status_checks[].context' "${tmp}.put"

gh api "repos/${REPO}/rulesets/${RULESET_ID}" -X PUT --input "${tmp}.put"

echo "Ruleset ${RULESET_ID} updated."
