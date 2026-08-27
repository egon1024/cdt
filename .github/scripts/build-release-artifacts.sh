#!/usr/bin/env bash
# Build release tarballs, .deb/.rpm packages, SBOM, and SHA256SUMS for a CDT bundle version.
# Run from repository root. Requires: cargo, strip, tar, nfpm, sha256sum, python3.
# Optional: cargo-cyclonedx (for SBOM generation).
set -euo pipefail

VERSION="${VERSION:?VERSION is required (e.g. 0.1.0)}"
ARCH="${ARCH:-amd64}"
RPM_ARCH="${RPM_ARCH:-x86_64}"
OUT_DIR="${OUT_DIR:-release-artifacts}"
NFPM="${NFPM:-nfpm}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

readarray -t BUILD_PACKAGES < <(python3 - <<'PY'
import tomllib
from pathlib import Path

manifest = tomllib.loads(Path("cdt-manifest.toml").read_text(encoding="utf-8"))
packages = ["cdt"]
for component in manifest["components"]:
    crate = component["crate"]
    if crate not in packages:
        packages.append(crate)
print("\n".join(packages))
PY
)

readarray -t BINARIES < <(python3 - <<'PY'
import tomllib
from pathlib import Path

manifest = tomllib.loads(Path("cdt-manifest.toml").read_text(encoding="utf-8"))
binaries = ["cdt"]
for component in manifest["components"]:
    binaries.append(component.get("binary", component["crate"]))
print("\n".join(binaries))
PY
)

mkdir -p "$OUT_DIR"
rm -rf packaging/staging packaging/staging-dbg
mkdir -p packaging/staging/usr/bin packaging/staging-dbg/usr/bin

echo "Building release binaries for ${VERSION}..."
pkg_args=()
for pkg in "${BUILD_PACKAGES[@]}"; do
  pkg_args+=(-p "$pkg")
done
cargo build --release "${pkg_args[@]}"

for bin in "${BINARIES[@]}"; do
  cp "target/release/${bin}" "packaging/staging-dbg/usr/bin/${bin}"
  cp "target/release/${bin}" "packaging/staging/usr/bin/${bin}"
  strip "packaging/staging/usr/bin/${bin}"
done

TARBALL_PROD="${OUT_DIR}/cdt-${VERSION}-${ARCH}.tar.gz"
TARBALL_DBG="${OUT_DIR}/cdt-${VERSION}-${ARCH}-debug.tar.gz"

pack_tarball() {
  local staging="$1"
  local output="$2"
  local tmp
  tmp="$(mktemp -d)"
  mkdir -p "${tmp}/cdt-${VERSION}"
  cp "${staging}/usr/bin/"* "${tmp}/cdt-${VERSION}/"
  cp LICENSE "${tmp}/cdt-${VERSION}/"
  if [[ -d docs ]]; then
    mkdir -p "${tmp}/cdt-${VERSION}/docs"
    cp -a docs/. "${tmp}/cdt-${VERSION}/docs/"
  fi
  tar -C "${tmp}" -czf "${output}" "cdt-${VERSION}"
  rm -rf "${tmp}"
}

echo "Creating tarballs..."
pack_tarball packaging/staging "$TARBALL_PROD"
pack_tarball packaging/staging-dbg "$TARBALL_DBG"

export VERSION
echo "Rendering nfpm configs..."
python3 .github/scripts/render-nfpm-config.py --variant prod >packaging/nfpm/cdt.generated.yaml
python3 .github/scripts/render-nfpm-config.py --variant dbg >packaging/nfpm/cdt-dbg.generated.yaml

if ! command -v "$NFPM" >/dev/null 2>&1; then
  echo "::error::nfpm not found (set NFPM or install from https://nfpm.goreleaser.com)"
  exit 1
fi

echo "Building .deb packages..."
"$NFPM" pkg --config packaging/nfpm/cdt.generated.yaml --packager deb --target "$OUT_DIR"
"$NFPM" pkg --config packaging/nfpm/cdt-dbg.generated.yaml --packager deb --target "$OUT_DIR"

DEB_PROD="${OUT_DIR}/cdt_${VERSION}_${ARCH}.deb"
DEB_DBG="${OUT_DIR}/cdt-dbg_${VERSION}_${ARCH}.deb"
for f in "$OUT_DIR"/*.deb; do
  [[ -e "$f" ]] || continue
  case "$(basename "$f")" in
    cdt_${VERSION}_*.deb)
      [[ "$f" != "$DEB_PROD" ]] && mv -f "$f" "$DEB_PROD"
      ;;
    cdt-dbg_${VERSION}_*.deb)
      [[ "$f" != "$DEB_DBG" ]] && mv -f "$f" "$DEB_DBG"
      ;;
  esac
done

echo "Building .rpm packages..."
"$NFPM" pkg --config packaging/nfpm/cdt.generated.yaml --packager rpm --target "$OUT_DIR"
"$NFPM" pkg --config packaging/nfpm/cdt-dbg.generated.yaml --packager rpm --target "$OUT_DIR"

RPM_PROD="${OUT_DIR}/cdt-${VERSION}-1.${RPM_ARCH}.rpm"
RPM_DBG="${OUT_DIR}/cdt-dbg-${VERSION}-1.${RPM_ARCH}.rpm"
for f in "$OUT_DIR"/*.rpm; do
  [[ -e "$f" ]] || continue
  case "$(basename "$f")" in
    cdt-${VERSION}*.rpm)
      [[ "$f" != "$RPM_PROD" ]] && mv -f "$f" "$RPM_PROD"
      ;;
    cdt-dbg-${VERSION}*.rpm)
      [[ "$f" != "$RPM_DBG" ]] && mv -f "$f" "$RPM_DBG"
      ;;
  esac
done

SBOM_PATH="${OUT_DIR}/cdt-${VERSION}.spdx.json"
checksum_files=(
  "$(basename "$TARBALL_PROD")"
  "$(basename "$TARBALL_DBG")"
  "$(basename "$DEB_PROD")"
  "$(basename "$DEB_DBG")"
  "$(basename "$RPM_PROD")"
  "$(basename "$RPM_DBG")"
)

if cargo cyclonedx --version >/dev/null 2>&1; then
  echo "Generating SBOM..."
  cargo cyclonedx --manifest-path crates/delve/Cargo.toml \
    --format json --all-features --describe crate -q
  mv "crates/delve/delve.cdx.json" "$SBOM_PATH"
  checksum_files+=("$(basename "$SBOM_PATH")")
else
  echo "cargo-cyclonedx not installed; skipping SBOM"
fi

echo "Generating SHA256SUMS..."
(
  cd "$OUT_DIR"
  sha256sum "${checksum_files[@]}" >SHA256SUMS
)

echo "Release artifacts in ${OUT_DIR}:"
ls -la "$OUT_DIR"
