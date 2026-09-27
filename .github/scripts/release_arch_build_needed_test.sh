#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release-asset-names.sh
source "${ROOT}/release-asset-names.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

mapfile -t amd64_names < <(release_arch_asset_names 1.2.3 amd64)
amd64_names+=("cdt-1.2.3.spdx.json")
amd64_list="$(printf '%s\n' "${amd64_names[@]}")"

export GITHUB_OUTPUT="$out"
export RELEASE_ARCH_BUILD_MOCK=1
export RELEASE_ARCH_BUILD_MOCK_EXISTING="${amd64_list}"
bash "${ROOT}/release-arch-build-needed.sh" 1.2.3 amd64 1 \
  || fail "complete amd64 should succeed"
grep -qx 'skip_build=true' "$out" || fail "expected skip_build=true"

: >"$out"
export RELEASE_ARCH_BUILD_MOCK=1
export RELEASE_ARCH_BUILD_MOCK_EXISTING="${amd64_names[0]}"
if bash "${ROOT}/release-arch-build-needed.sh" 1.2.3 amd64 1 2>/dev/null; then
  fail "partial amd64 should fail"
fi

: >"$out"
export RELEASE_ARCH_BUILD_MOCK_EXISTING=""
bash "${ROOT}/release-arch-build-needed.sh" 1.2.3 arm64 0 \
  || fail "empty release should allow build"
grep -qx 'skip_build=false' "$out" || fail "expected skip_build=false"

echo "release-arch-build-needed tests passed"
