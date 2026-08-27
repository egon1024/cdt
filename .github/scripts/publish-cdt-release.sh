#!/usr/bin/env bash
# Create a cdt-v* GitHub release for the bundle version on RELEASE_BRANCH.
set -euo pipefail

VERSION="${1:?VERSION is required (e.g. 0.3.0)}"
RELEASE_BRANCH="${RELEASE_BRANCH:-main}"
TAG="cdt-v${VERSION}"

if gh release view "${TAG}" >/dev/null 2>&1; then
  echo "Release ${TAG} already exists; skipping create."
  exit 0
fi

python3 .github/scripts/cdt-versions.py component-versions-json >.release-component-versions.json
notes_file="$(mktemp)"
python3 .github/scripts/cdt-versions.py release-notes \
  --version "${VERSION}" \
  --component-versions "$(cat .release-component-versions.json)" >"${notes_file}"

gh release create "${TAG}" \
  --target "${RELEASE_BRANCH}" \
  --title "cdt ${VERSION}" \
  --notes-file "${notes_file}"
rm -f "${notes_file}"

echo "Created GitHub release ${TAG}."
