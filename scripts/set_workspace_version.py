#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path


WORKSPACE_PACKAGES = {
    "schlussel",
    "schlussel-cli",
    "schlussel-oauth-test-server",
}


def set_workspace_version(repo_root: Path, version: str) -> None:
    cargo_toml = repo_root / "Cargo.toml"
    cargo_lock = repo_root / "Cargo.lock"

    update_workspace_manifest(cargo_toml, version)
    update_lockfile(cargo_lock, version)


def update_workspace_manifest(path: Path, version: str) -> None:
    lines = path.read_text().splitlines()
    in_workspace_package = False

    for index, line in enumerate(lines):
        if line.startswith("[") and line.endswith("]"):
            in_workspace_package = line == "[workspace.package]"
            continue

        if in_workspace_package and line.startswith("version = "):
            lines[index] = f'version = "{version}"'
            path.write_text("\n".join(lines) + "\n")
            return

    raise SystemExit(f"could not find workspace version in {path}")


def update_lockfile(path: Path, version: str) -> None:
    lines = path.read_text().splitlines()
    in_package = False
    current_name: str | None = None
    updated_packages: set[str] = set()

    for index, line in enumerate(lines):
        if line == "[[package]]":
            in_package = True
            current_name = None
            continue

        if line.startswith("[") and line != "[[package]]":
            in_package = False
            current_name = None
            continue

        if not in_package:
            continue

        if line.startswith('name = "'):
            current_name = line[len('name = "') : -1]
            continue

        if (
            current_name in WORKSPACE_PACKAGES
            and line.startswith('version = "')
            and current_name not in updated_packages
        ):
            lines[index] = f'version = "{version}"'
            updated_packages.add(current_name)

    if updated_packages != WORKSPACE_PACKAGES:
        missing = ", ".join(sorted(WORKSPACE_PACKAGES - updated_packages))
        raise SystemExit(f"could not update lockfile entries for: {missing}")

    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Update the workspace version in Cargo.toml and Cargo.lock."
    )
    parser.add_argument("version", help="Version to stamp into the workspace metadata.")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    set_workspace_version(repo_root, args.version)


if __name__ == "__main__":
    main()
