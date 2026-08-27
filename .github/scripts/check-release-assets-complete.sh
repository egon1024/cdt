#!/usr/bin/env bash
# Return 0 when a cdt-v* release has all expected assets; 1 otherwise.
set -euo pipefail

VERSION="${1:?VERSION is required (e.g. 0.3.0)}"
TAG="cdt-v${VERSION}"

if ! gh release view "${TAG}" >/dev/null 2>&1; then
  echo "Release ${TAG} does not exist"
  exit 1
fi

expected=(
  "cdt-${VERSION}-amd64.tar.gz"
  "cdt-${VERSION}-amd64-debug.tar.gz"
  "cdt_${VERSION}_amd64.deb"
  "cdt-dbg_${VERSION}_amd64.deb"
  "cdt-${VERSION}-1.x86_64.rpm"
  "cdt-dbg-${VERSION}-1.x86_64.rpm"
  "cdt-${VERSION}.spdx.json"
  "SHA256SUMS"
)

existing="$(gh release view "${TAG}" --json assets --jq '.assets[].name' || true)"
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
