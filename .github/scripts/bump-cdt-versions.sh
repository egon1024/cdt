#!/usr/bin/env bash
# Apply bundle and component version bumps from cdt-manifest.toml.
set -euo pipefail

BUNDLE_VERSION="${BUNDLE_VERSION:?BUNDLE_VERSION is required}"

if [[ -n "${COMPONENT_VERSIONS_FILE:-}" ]]; then
  COMPONENT_VERSIONS="$(cat "$COMPONENT_VERSIONS_FILE")"
elif [[ -n "${COMPONENT_VERSIONS:-}" ]]; then
  :
else
  echo "::error::COMPONENT_VERSIONS or COMPONENT_VERSIONS_FILE is required"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 "${ROOT_DIR}/.github/scripts/cdt-versions.py" apply \
  --bundle-version "$BUNDLE_VERSION" \
  --component-versions "$COMPONENT_VERSIONS"

if ! command -v cargo >/dev/null 2>&1; then
  echo "::error::cargo not found; cannot regenerate Cargo.lock"
  exit 1
fi

echo "Regenerating Cargo.lock for bundle ${BUNDLE_VERSION}"
cargo update --workspace --manifest-path "${ROOT_DIR}/Cargo.toml"
