#!/usr/bin/env bash
# Replace prior version-preview bot comments and post the latest preview or error.
set -euo pipefail

MARKER="<!-- cdt-version-preview -->"
PR_NUMBER="${PR_NUMBER:?PR_NUMBER is required}"
ERROR="${VERSION_ERROR:-}"
CURRENT="${CURRENT_BUNDLE_VERSION:-${CURRENT_VERSION:-}}"
NEXT="${NEXT_BUNDLE_VERSION:-${NEXT_VERSION:-}}"
BUMP_LEVEL="${BUNDLE_BUMP_LEVEL:-${BUMP_LEVEL:-}}"
BUMP_SOURCE="${BUNDLE_BUMP_SOURCE:-${BUMP_SOURCE:-}}"
COMPONENT_VERSIONS="${COMPONENT_VERSIONS:-}"

delete_prior_comments() {
  gh api "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" --paginate \
    --jq ".[] | select(.body | contains(\"${MARKER}\")) | .id" |
    while read -r comment_id; do
      [[ -z "$comment_id" ]] && continue
      gh api --method DELETE "repos/${GITHUB_REPOSITORY}/issues/comments/${comment_id}"
    done
}

component_table() {
  if [[ -z "$COMPONENT_VERSIONS" ]]; then
    return
  fi

  python3 - <<'PY' "$COMPONENT_VERSIONS"
import json
import sys

versions = json.loads(sys.argv[1])
print("| Utility | Version after merge |")
print("|---------|---------------------|")
for name in sorted(versions):
    print(f"| `{name}` | `{versions[name]}` |")
PY
}

build_body() {
  if [[ -n "$ERROR" ]]; then
    cat <<EOF
${MARKER}
## Version preview — failed

The PR description contains **conflicting** bundle semver directives. Use at most one of \`#cdt:major\`, \`#cdt:minor\`, \`#cdt:patch\`, or the shorthand \`#major\` / \`#minor\` / \`#patch\`.

Per-utility directives such as \`#delve:patch\` may also be used.

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
| Current bundle (\`cdt\`) | \`${CURRENT}\` |
| Bundle bump | **${BUMP_LEVEL}** (${source_label}) |
| Next bundle (if merged) | \`${NEXT}\` |
| Release tag | \`cdt-v${NEXT}\` |

### Utilities in this bundle

$(component_table)

### Directives

- Bundle: \`#cdt:minor\` or shorthand \`#minor\` (default: minor)
- Utility: \`#delve:patch\`, \`#delve:minor\`, etc.
- Utilities with changes under \`crates/<utility>/\` receive an automatic **patch** bump unless overridden.
EOF
}

delete_prior_comments
BODY_FILE="$(mktemp)"
build_body >"$BODY_FILE"
gh pr comment "$PR_NUMBER" --body-file "$BODY_FILE"
rm -f "$BODY_FILE"
