#!/usr/bin/env python3
"""Manage CDT bundle and component versions via cdt-manifest.toml."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "cdt-manifest.toml"
ROOT_CARGO = ROOT / "Cargo.toml"


@dataclass
class Component:
    name: str
    crate: str
    binary: str
    version: str
    description: str
    path: Path

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Component:
        crate = data["crate"]
        return cls(
            name=data["name"],
            crate=crate,
            binary=data.get("binary", crate),
            version=data["version"],
            description=data.get("description", ""),
            path=ROOT / "crates" / crate,
        )


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def set_manifest_bundle_version(version: str, path: Path = MANIFEST_PATH) -> None:
    text = path.read_text(encoding="utf-8")
    new_text, count = re.subn(
        r'(\[bundle\][\s\S]*?^version = )"[^"]+"',
        rf'\1"{version}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise RuntimeError("could not update bundle version in cdt-manifest.toml")
    path.write_text(new_text, encoding="utf-8")


def set_manifest_component_version(
    component_name: str, version: str, path: Path = MANIFEST_PATH
) -> None:
    text = path.read_text(encoding="utf-8")
    pattern = (
        rf'(\[\[components\]\][\s\S]*?^name = "{re.escape(component_name)}"'
        rf'[\s\S]*?^version = )"[^"]+"'
    )
    new_text, count = re.subn(pattern, rf'\1"{version}"', text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError(
            f"could not update component {component_name} version in cdt-manifest.toml"
        )
    path.write_text(new_text, encoding="utf-8")


def bump_semver(version: str, level: str) -> str:
    major, minor, patch = (int(part) for part in version.split("."))
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    if level == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"invalid bump level: {level}")


def parse_directives(pr_body: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for raw_line in pr_body.splitlines():
        line = raw_line.strip()
        match = re.fullmatch(r"#(?P<target>[a-z0-9-]+):(?P<level>major|minor|patch)", line, re.I)
        if match:
            directives[match.group("target").lower()] = match.group("level").lower()
            continue
        match = re.fullmatch(r"#(?P<level>major|minor|patch)", line, re.I)
        if match:
            directives["cdt"] = match.group("level").lower()
    return directives


def component_changed(component: Component, changed_files: list[str]) -> bool:
    prefix = f"crates/{component.crate}/"
    for path in changed_files:
        if path.startswith(prefix):
            return True
    return False


def compute_component_versions(
    manifest: dict[str, Any],
    changed_files: list[str],
    directives: dict[str, str],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in manifest.get("components", []):
        component = Component.from_dict(entry)
        current = component.version
        if component.name in directives:
            result[component.name] = bump_semver(current, directives[component.name])
        elif component_changed(component, changed_files):
            result[component.name] = bump_semver(current, "patch")
        else:
            result[component.name] = current
    return result


def set_crate_version(crate_toml: Path, version: str) -> None:
    text = crate_toml.read_text(encoding="utf-8")
    pattern = r'(^version = )"[^"]+"'
    new_text, count = re.subn(pattern, rf'\1"{version}"', text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError(f"could not update version in {crate_toml}")
    crate_toml.write_text(new_text, encoding="utf-8")


def set_workspace_version(version: str) -> None:
    text = ROOT_CARGO.read_text(encoding="utf-8")
    pattern = r'(\[workspace\.package\][\s\S]*?^version = )"[^"]+"'
    new_text, count = re.subn(
        pattern, rf'\1"{version}"', text, count=1, flags=re.MULTILINE
    )
    if count != 1:
        raise RuntimeError("could not update [workspace.package].version")
    ROOT_CARGO.write_text(new_text, encoding="utf-8")


def apply_release(bundle_version: str, component_versions: dict[str, str]) -> None:
    set_manifest_bundle_version(bundle_version)
    for name, version in component_versions.items():
        set_manifest_component_version(name, version)

    set_workspace_version(bundle_version)
    set_crate_version(ROOT / "crates" / "cdt" / "Cargo.toml", bundle_version)

    manifest = load_manifest()
    for entry in manifest.get("components", []):
        component = Component.from_dict(entry)
        version = component_versions.get(component.name, component.version)
        set_crate_version(component.path / "Cargo.toml", version)


def normalize_release_tag(tag: str) -> str | None:
    tag = tag.strip()
    for prefix in ("cdt-v", "cdt-V", "v", "V"):
        if tag.startswith(prefix):
            tag = tag[len(prefix) :]
            break
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", tag):
        return tag
    return None


def resolve_current_bundle_version() -> str:
    versions: list[str] = []
    if MANIFEST_PATH.exists():
        versions.append(load_manifest()["bundle"]["version"])

    import subprocess

    for args in (
        ["git", "tag", "--list", "cdt-v*"],
        ["git", "tag", "--list", "v*"],
        ["git", "tag", "--list", "[0-9]*.[0-9]*.[0-9]*"],
    ):
        result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            normalized = normalize_release_tag(line)
            if normalized:
                versions.append(normalized)

    if not versions:
        return "0.0.0"
    return sorted(versions, key=lambda v: tuple(int(p) for p in v.split(".")))[-1]


def cmd_preview(args: argparse.Namespace) -> int:
    current = resolve_current_bundle_version()
    directives = parse_directives(args.pr_body or "")

    bundle_levels = {level for target, level in directives.items() if target == "cdt"}
    if len(bundle_levels) > 1:
        print("::error::Conflicting bundle semver directives (#cdt:... or #major/#minor/#patch)")
        if args.format == "github-output" and args.github_output:
            with open(args.github_output, "a", encoding="utf-8") as handle:
                handle.write("error=conflicting_bundle_directives\n")
        return 1

    bundle_level = directives.get("cdt", args.default_bump)
    next_bundle = bump_semver(current, bundle_level)
    changed_files = [
        line.strip() for line in (args.changed_files or "").splitlines() if line.strip()
    ]
    manifest = load_manifest()
    component_versions = compute_component_versions(manifest, changed_files, directives)

    if args.format == "github-output" and args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as handle:
            handle.write("error=\n")
            handle.write(f"current_bundle_version={current}\n")
            handle.write(f"next_bundle_version={next_bundle}\n")
            handle.write(f"bundle_bump_level={bundle_level}\n")
            source = "explicit" if "cdt" in directives else "implicit"
            handle.write(f"bundle_bump_source={source}\n")
            handle.write(
                "component_versions="
                + json.dumps(component_versions, separators=(",", ":"))
                + "\n"
            )
    else:
        print(
            json.dumps(
                {
                    "current_bundle_version": current,
                    "next_bundle_version": next_bundle,
                    "bundle_bump_level": bundle_level,
                    "component_versions": component_versions,
                },
                indent=2,
            )
        )
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    component_versions = json.loads(args.component_versions)
    apply_release(args.bundle_version, component_versions)
    print(f"Updated bundle to {args.bundle_version}")
    for name, version in component_versions.items():
        print(f"  {name}: {version}")
    return 0


def cmd_show(_: argparse.Namespace) -> int:
    print(json.dumps(load_manifest(), indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    preview = sub.add_parser("preview")
    preview.add_argument("--pr-body", default="")
    preview.add_argument("--default-bump", default="minor")
    preview.add_argument("--changed-files", default="")
    preview.add_argument("--format", choices=("json", "github-output"), default="json")
    preview.add_argument("--github-output")
    preview.set_defaults(func=cmd_preview)

    apply_cmd = sub.add_parser("apply")
    apply_cmd.add_argument("--bundle-version", required=True)
    apply_cmd.add_argument("--component-versions", required=True)
    apply_cmd.set_defaults(func=cmd_apply)

    show = sub.add_parser("show")
    show.set_defaults(func=cmd_show)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
