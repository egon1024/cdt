#!/usr/bin/env bash
# Resolve the bundle version to publish and write it to GITHUB_OUTPUT as "version".
set -euo pipefail

prepare_version="${PREPARE_VERSION:-}"
manual_version="${MANUAL_VERSION:-}"
commit_message="${COMMIT_MESSAGE:-}"

if [[ -n "${prepare_version}" ]]; then
  version="${prepare_version}"
elif [[ -n "${manual_version}" ]]; then
  version="${manual_version}"
elif [[ "${commit_message}" =~ chore:[[:space:]]release[[:space:]]cdt[[:space:]]([0-9]+\.[0-9]+\.[0-9]+) ]]; then
  version="${BASH_REMATCH[1]}"
else
  version="$(python3 -c 'import json, tomllib, pathlib; print(tomllib.loads(pathlib.Path("cdt-manifest.toml").read_text())["bundle"]["version"])')"
fi

if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::Resolved publish version is invalid: ${version:-empty}"
  exit 1
fi

{
  echo "version=${version}"
} >>"${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"

echo "Resolved publish version: ${version}"
