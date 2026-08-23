#!/usr/bin/env bash
# Set workspace.package.version in the root Cargo.toml and resync Cargo.lock.
set -euo pipefail

NEXT_VERSION="${NEXT_VERSION:?NEXT_VERSION is required}"
ROOT_CARGO="${ROOT_CARGO:-Cargo.toml}"

if [[ ! -f "$ROOT_CARGO" ]]; then
  echo "::error::Missing ${ROOT_CARGO}"
  exit 1
fi

python3 - "$ROOT_CARGO" "$NEXT_VERSION" <<'PY'
import re
import sys

path, version = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()

pattern = r'(\[workspace\.package\][\s\S]*?^version = )"[^"]+"'
replacement = rf'\1"{version}"'
new_text, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)

if count != 1:
    print(f"::error::Could not update [workspace.package] version in {path}", file=sys.stderr)
    sys.exit(1)

open(path, "w", encoding="utf-8").write(new_text)
print(f"Updated workspace.package.version to {version}")
PY

if ! command -v cargo >/dev/null 2>&1; then
  echo "::error::cargo not found; cannot regenerate Cargo.lock for ${NEXT_VERSION}"
  exit 1
fi

echo "Regenerating Cargo.lock workspace entries for ${NEXT_VERSION}"
cargo update --workspace --manifest-path "$ROOT_CARGO"
