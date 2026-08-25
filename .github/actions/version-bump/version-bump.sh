#!/usr/bin/env bash
# Compute next CDT bundle and component versions from manifest, tags, and PR directives.
set -euo pipefail

PR_BODY="${PR_BODY:-}"
DEFAULT_BUMP="${DEFAULT_BUMP:-minor}"
CHANGED_FILES="${CHANGED_FILES:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

python3 "${ROOT_DIR}/.github/scripts/cdt-versions.py" preview \
  --pr-body "$PR_BODY" \
  --default-bump "$DEFAULT_BUMP" \
  --changed-files "$CHANGED_FILES" \
  --format github-output \
  --github-output "${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"

# Legacy output names used by existing workflows.
if grep -q '^current_bundle_version=' "${GITHUB_OUTPUT}"; then
  current="$(grep '^current_bundle_version=' "${GITHUB_OUTPUT}" | tail -1 | cut -d= -f2-)"
  next="$(grep '^next_bundle_version=' "${GITHUB_OUTPUT}" | tail -1 | cut -d= -f2-)"
  level="$(grep '^bundle_bump_level=' "${GITHUB_OUTPUT}" | tail -1 | cut -d= -f2-)"
  source="$(grep '^bundle_bump_source=' "${GITHUB_OUTPUT}" | tail -1 | cut -d= -f2-)"
  {
    echo "current_version=${current}"
    echo "next_version=${next}"
    echo "bump_level=${level}"
    echo "bump_source=${source}"
  } >>"${GITHUB_OUTPUT}"
fi
