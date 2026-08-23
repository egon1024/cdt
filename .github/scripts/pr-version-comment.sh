#!/usr/bin/env bash
# Replace prior version-preview bot comments and post the latest preview or error.
set -euo pipefail

MARKER="<!-- cdt-version-preview -->"
PR_NUMBER="${PR_NUMBER:?PR_NUMBER is required}"
ERROR="${VERSION_ERROR:-}"
CURRENT="${CURRENT_VERSION:-}"
NEXT="${NEXT_VERSION:-}"
BUMP_LEVEL="${BUMP_LEVEL:-}"
BUMP_SOURCE="${BUMP_SOURCE:-}"

delete_prior_comments() {
  gh api "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" --paginate \
    --jq ".[] | select(.body | contains(\"${MARKER}\")) | .id" |
    while read -r comment_id; do
      [[ -z "$comment_id" ]] && continue
      gh api --method DELETE "repos/${GITHUB_REPOSITORY}/issues/comments/${comment_id}"
    done
}

build_body() {
  if [[ -n "$ERROR" ]]; then
    cat <<EOF
${MARKER}
## Version preview — failed

The PR description contains **conflicting** semver directives. Use at most one line containing only \`#major\`, \`#minor\`, or \`#patch\` (case-insensitive).

**Error:** \`${ERROR}\`
EOF
    return
  fi

  local source_label="implicit"
  if [[ "$BUMP_SOURCE" == "explicit" ]]; then
    source_label="explicit"
  fi

  cat <<EOF
${MARKER}
## Version preview

| Field | Value |
|-------|-------|
| Current release | \`${CURRENT}\` |
| Bump level | **${BUMP_LEVEL}** (${source_label}) |
| Next version (if merged) | \`${NEXT}\` |

Set bump explicitly by adding a line containing only \`#major\`, \`#minor\`, or \`#patch\` (case-insensitive) in the PR description. Do not use more than one bump level — conflicting lines fail this check.
EOF
}

delete_prior_comments
BODY_FILE="$(mktemp)"
build_body >"$BODY_FILE"
gh pr comment "$PR_NUMBER" --body-file "$BODY_FILE"
rm -f "$BODY_FILE"
