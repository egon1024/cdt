#!/usr/bin/env bash
# Merge SHA256SUMS for all uploaded release assets (multi-arch matrix builds).
set -euo pipefail

VERSION="${1:?VERSION is required (e.g. 0.1.0)}"
TAG="cdt-v${VERSION}"
OUT_DIR="${OUT_DIR:-release-artifacts-merge}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

mapfile -t asset_names < <(
  gh release view "${TAG}" --json assets --jq '.assets[].name' | grep -v '^SHA256SUMS$' || true
)

if ((${#asset_names[@]} == 0)); then
  echo "::error::No release assets found for ${TAG}"
  exit 1
fi

for name in "${asset_names[@]}"; do
  gh release download "${TAG}" -p "${name}" -D "${OUT_DIR}"
done

(
  cd "$OUT_DIR"
  sha256sum "${asset_names[@]}" >SHA256SUMS
)

echo "Merged SHA256SUMS for ${#asset_names[@]} assets"
cat "${OUT_DIR}/SHA256SUMS"
