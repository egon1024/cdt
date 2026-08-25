#!/usr/bin/env bash
# Apply bundle and component version bumps from cdt-manifest.toml.
set -euo pipefail

BUNDLE_VERSION="${BUNDLE_VERSION:?BUNDLE_VERSION is required}"
COMPONENT_VERSIONS="${COMPONENT_VERSIONS:?COMPONENT_VERSIONS is required}"

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
