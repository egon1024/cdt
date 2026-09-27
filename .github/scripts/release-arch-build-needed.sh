#!/usr/bin/env bash
# Decide whether a release-artifacts matrix leg should build for an architecture.
# Writes skip_build=true to GITHUB_OUTPUT when all expected assets for ARCH exist.
# Fails when some but not all expected assets exist (partial upload).
set -euo pipefail

VERSION="${1:?VERSION required}"
ARCH="${2:?ARCH required (amd64 or arm64)}"
GENERATE_SBOM="${3:-0}"
RELEASE_TAG="cdt-v${VERSION}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release-asset-names.sh
source "${ROOT}/release-asset-names.sh"

if [[ "${RELEASE_ARCH_BUILD_MOCK:-}" == "1" ]]; then
  existing="${RELEASE_ARCH_BUILD_MOCK_EXISTING-}"
else
  if ! gh release view "${RELEASE_TAG}" >/dev/null 2>&1; then
    echo "::error::GitHub release ${RELEASE_TAG} does not exist yet"
    exit 1
  fi
  existing="$(gh release view "${RELEASE_TAG}" --json assets --jq '.assets[].name' || true)"
fi

mapfile -t expected < <(release_arch_asset_names "${VERSION}" "${ARCH}")
if [[ "${GENERATE_SBOM}" == "1" ]]; then
  expected+=("cdt-${VERSION}.spdx.json")
fi

missing=()
present=()
for name in "${expected[@]}"; do
  if echo "${existing}" | grep -qx "${name}"; then
    present+=("${name}")
  else
    missing+=("${name}")
  fi
done

if ((${#missing[@]} == 0)); then
  echo "All ${#expected[@]} release asset(s) for ${ARCH} already on ${RELEASE_TAG}; skipping build."
  echo "skip_build=true" >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"
  exit 0
fi

if ((${#present[@]} > 0)); then
  echo "::error::Partial ${ARCH} assets on ${RELEASE_TAG}; missing: ${missing[*]}. Present: ${present[*]}. Delete conflicting assets or upload missing files manually."
  exit 1
fi

echo "Building ${#expected[@]} ${ARCH} asset(s) for ${RELEASE_TAG}."
echo "skip_build=false" >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"
