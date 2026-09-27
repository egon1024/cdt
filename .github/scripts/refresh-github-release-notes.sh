#!/usr/bin/env bash
# Regenerate and apply GitHub release notes from docs/release-notes on the current checkout.
set -euo pipefail

VERSION="${1:?VERSION is required (e.g. 0.8.0)}"
TAG="cdt-v${VERSION}"

if ! gh release view "${TAG}" >/dev/null 2>&1; then
  echo "::error::Release ${TAG} not found"
  exit 1
fi

notes_file="$(mktemp)"
trap 'rm -f "$notes_file"' EXIT

python3 .github/scripts/cdt-versions.py component-versions-json >.release-component-versions.json
python3 .github/scripts/cdt-versions.py release-notes \
  --version "${VERSION}" \
  --component-versions "$(cat .release-component-versions.json)" >"${notes_file}"

gh release edit "${TAG}" --notes-file "${notes_file}"
echo "Updated release notes for ${TAG}."
