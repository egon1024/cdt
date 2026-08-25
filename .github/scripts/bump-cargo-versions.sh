#!/usr/bin/env bash
# Deprecated: use bump-cdt-versions.sh instead.
set -euo pipefail
echo "::warning::bump-cargo-versions.sh is deprecated; use bump-cdt-versions.sh" >&2
exec bash "$(dirname "$0")/bump-cdt-versions.sh"
