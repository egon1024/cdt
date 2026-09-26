#!/usr/bin/env bash
# Regression tests for release asset completeness expectations.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT/.."

source "${ROOT}/release-asset-names.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

mapfile -t all_expected < <(release_expected_asset_names "1.2.3")
if ((${#all_expected[@]} != 14)); then
  fail "expected 14 release assets, got ${#all_expected[@]}"
fi

for name in \
  "cdt_1.2.3_arm64.deb" \
  "cdt-1.2.3-1.aarch64.rpm" \
  "cdt-1.2.3-arm64.tar.gz"; do
  if ! printf '%s\n' "${all_expected[@]}" | grep -qx "$name"; then
    fail "missing arm64 asset name: $name"
  fi
done

amd64_only="$(release_arch_asset_names 1.2.3 amd64)"
CHECK_RELEASE_ASSETS_MOCK="${amd64_only}" bash "${ROOT}/check-release-assets-complete.sh" 1.2.3 \
  && fail "expected failure when arm64 assets missing"

full_list="$(release_expected_asset_names 1.2.3)"
CHECK_RELEASE_ASSETS_MOCK="${full_list}" bash "${ROOT}/check-release-assets-complete.sh" 1.2.3 \
  || fail "expected success with full asset list"

echo "check-release-assets-complete tests passed"
