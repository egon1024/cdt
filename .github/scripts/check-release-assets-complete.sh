#!/usr/bin/env bash
# Return 0 when a cdt-v* release has all expected assets; 1 otherwise.
# Expected amd64 + arm64 asset names: release-asset-names.sh (sourced below).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release-asset-names.sh
source "${ROOT}/release-asset-names.sh"

VERSION="${1:?VERSION is required (e.g. 0.3.0)}"
TAG="cdt-v${VERSION}"

if [[ -n "${CHECK_RELEASE_ASSETS_MOCK:-}" ]]; then
  existing="${CHECK_RELEASE_ASSETS_MOCK}"
elif ! gh release view "${TAG}" >/dev/null 2>&1; then
  echo "Release ${TAG} does not exist"
  exit 1
else
  existing="$(gh release view "${TAG}" --json assets --jq '.assets[].name' || true)"
fi

mapfile -t expected < <(release_expected_asset_names "${VERSION}")

missing=()
for name in "${expected[@]}"; do
  if ! grep -qx "${name}" <<<"${existing}"; then
    missing+=("${name}")
  fi
done

if ((${#missing[@]} > 0)); then
  echo "Release ${TAG} is missing assets: ${missing[*]}"
  exit 1
fi

echo "Release ${TAG} has all expected assets"
exit 0
