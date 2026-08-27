# Local checks aligned with .github/workflows/ci.yml
#
# make test      — fmt-check, clippy, and unit tests (CI parity)
# make fmt-check — verify formatting only
# make clippy    — workspace clippy with warnings denied
# make unit      — cargo test --workspace
# make fmt       — apply rustfmt (fix formatting)
# make build     — cargo build --workspace
# make check     — cargo check --workspace --all-targets
#

CARGO ?= cargo
CLIPPY_FLAGS := --workspace --all-targets -- -D warnings
VERSION ?= $(shell python3 -c 'import tomllib, pathlib; print(tomllib.loads(pathlib.Path("cdt-manifest.toml").read_text())["bundle"]["version"])')

.PHONY: help test fmt fmt-check clippy unit build check version release-artifacts

help:
	@echo "cdt Makefile targets:"
	@echo "  make test       Run fmt-check, clippy, and unit tests (same order as CI)"
	@echo "  make fmt-check  Check formatting (cargo fmt --check)"
	@echo "  make fmt        Apply rustfmt"
	@echo "  make clippy     Run clippy (-D warnings)"
	@echo "  make unit       Run cargo test --workspace"
	@echo "  make build      Build all workspace crates"
	@echo "  make check      Run cargo check --workspace --all-targets"
	@echo "  make version    Show CDT bundle manifest"
	@echo "  make release-artifacts  Build local .deb/tarballs (VERSION=0.1.0)"

test: fmt-check clippy unit

fmt-check:
	$(CARGO) fmt --all -- --check

fmt:
	$(CARGO) fmt --all

clippy:
	$(CARGO) clippy $(CLIPPY_FLAGS)

unit:
	$(CARGO) test --workspace

build:
	$(CARGO) build --workspace

check:
	$(CARGO) check --workspace --all-targets

version:
	@python3 .github/scripts/cdt-versions.py show
	@$(CARGO) run -q -p cdt -- version

release-artifacts:
	VERSION=$(VERSION) bash .github/scripts/build-release-artifacts.sh
