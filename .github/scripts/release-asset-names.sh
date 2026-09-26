#!/usr/bin/env bash
# Shared expected GitHub release asset names for a bundle version.
# Sourced by completeness and verification scripts; do not execute directly.
set -euo pipefail

release_expected_asset_names() {
  local version="${1:?version required}"
  cat <<EOF
cdt-${version}-amd64.tar.gz
cdt-${version}-amd64-debug.tar.gz
cdt_${version}_amd64.deb
cdt-dbg_${version}_amd64.deb
cdt-${version}-1.x86_64.rpm
cdt-dbg-${version}-1.x86_64.rpm
cdt-${version}-arm64.tar.gz
cdt-${version}-arm64-debug.tar.gz
cdt_${version}_arm64.deb
cdt-dbg_${version}_arm64.deb
cdt-${version}-1.aarch64.rpm
cdt-dbg-${version}-1.aarch64.rpm
cdt-${version}.spdx.json
SHA256SUMS
EOF
}

release_arch_asset_names() {
  local version="${1:?version required}"
  local arch="${2:?arch required (amd64 or arm64)}"
  case "$arch" in
    amd64)
      cat <<EOF
cdt-${version}-amd64.tar.gz
cdt-${version}-amd64-debug.tar.gz
cdt_${version}_amd64.deb
cdt-dbg_${version}_amd64.deb
cdt-${version}-1.x86_64.rpm
cdt-dbg-${version}-1.x86_64.rpm
EOF
      ;;
    arm64)
      cat <<EOF
cdt-${version}-arm64.tar.gz
cdt-${version}-arm64-debug.tar.gz
cdt_${version}_arm64.deb
cdt-dbg_${version}_arm64.deb
cdt-${version}-1.aarch64.rpm
cdt-dbg-${version}-1.aarch64.rpm
EOF
      ;;
    *)
      echo "::error::Unsupported arch: ${arch}" >&2
      return 1
      ;;
  esac
}
