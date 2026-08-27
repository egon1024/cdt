#!/usr/bin/env bash
# Verify release artifact outputs and SHA256SUMS.
# Run from repository root after build-release-artifacts.sh.
set -euo pipefail

OUT_DIR="${OUT_DIR:-release-artifacts}"

if [[ ! -d "$OUT_DIR" ]]; then
  echo "::error::Missing output directory: ${OUT_DIR}"
  exit 1
fi

required_patterns=(
  'cdt-*-amd64.tar.gz'
  'cdt-*-amd64-debug.tar.gz'
  'cdt_*_amd64.deb'
  'cdt-dbg_*_amd64.deb'
  'cdt-*-1.x86_64.rpm'
  'cdt-dbg-*-1.x86_64.rpm'
  'cdt-*.spdx.json'
  'SHA256SUMS'
)

for pattern in "${required_patterns[@]}"; do
  matches=( "$OUT_DIR"/$pattern )
  if [[ ! -e "${matches[0]}" ]]; then
    echo "::error::Missing artifact matching ${OUT_DIR}/${pattern}"
    exit 1
  fi
done

if ! (cd "$OUT_DIR" && sha256sum -c SHA256SUMS); then
  echo "::error::SHA256SUMS verification failed"
  exit 1
fi

echo "Verified release artifacts in ${OUT_DIR}:"
ls -la "$OUT_DIR"
