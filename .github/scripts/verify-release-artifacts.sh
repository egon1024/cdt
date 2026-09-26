#!/usr/bin/env bash
# Verify release artifact outputs and SHA256SUMS.
# Run from repository root after build-release-artifacts.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release-asset-names.sh
source "${ROOT}/release-asset-names.sh"

OUT_DIR="${OUT_DIR:-release-artifacts}"
ARCH="${ARCH:-amd64}"
VERSION="${VERSION:-${PACKAGE_VERSION:-}}"

if [[ ! -d "$OUT_DIR" ]]; then
  echo "::error::Missing output directory: ${OUT_DIR}"
  exit 1
fi

if [[ -z "$VERSION" ]]; then
  tarball=( "$OUT_DIR"/cdt-*-"${ARCH}".tar.gz )
  if [[ ! -e "${tarball[0]}" ]]; then
    echo "::error::Set VERSION or ensure ${OUT_DIR}/cdt-*-${ARCH}.tar.gz exists"
    exit 1
  fi
  base="$(basename "${tarball[0]}")"
  VERSION="${base#cdt-}"
  VERSION="${VERSION%-${ARCH}.tar.gz}"
fi

mapfile -t required < <(release_arch_asset_names "${VERSION}" "${ARCH}")

if [[ "${GENERATE_SBOM:-1}" == "1" && "$ARCH" == amd64 ]]; then
  required+=("cdt-${VERSION}.spdx.json")
fi

if [[ "${SKIP_SHA256SUMS:-0}" != "1" ]]; then
  required+=("SHA256SUMS")
fi

for name in "${required[@]}"; do
  if [[ ! -e "${OUT_DIR}/${name}" ]]; then
    echo "::error::Missing artifact ${OUT_DIR}/${name}"
    exit 1
  fi
done

if [[ -f "${OUT_DIR}/SHA256SUMS" ]]; then
  if ! (cd "$OUT_DIR" && sha256sum -c SHA256SUMS); then
    echo "::error::SHA256SUMS verification failed"
    exit 1
  fi
fi

echo "Verified release artifacts in ${OUT_DIR} (${ARCH}):"
ls -la "$OUT_DIR"
