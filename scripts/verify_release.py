#!/usr/bin/env python3
"""Release gate for FreezeSentryF4: a package tree must match build outputs.

Catches stale-binary packaging (a rebuilt Watch paired with an old DLL, or an
old binary shipped under a release name) and INI/Code config drift.

Usage:
    python scripts/verify_release.py --build build --package <dir-or-zip>

Checks:
    1. Required files exist in the package (DLL, Watch EXE, INI; PDBs warn).
    2. DLL and EXE are byte-identical (SHA-256) to the build outputs.
    3. Every setting() key read by src/plugin.cpp is documented in dist INI.
"""
import argparse
import hashlib
import re
import sys
import tempfile
import zipfile
from pathlib import Path

REQUIRED = [
    "F4SE/Plugins/FreezeSentryF4.dll",
    "F4SE/Plugins/FreezeSentryF4Watch.exe",
    "F4SE/Plugins/FreezeSentryF4.ini",
]
PDBS = [
    "F4SE/Plugins/FreezeSentryF4.pdb",
    "F4SE/Plugins/FreezeSentryF4Watch.pdb",
]
BUILD_BINARIES = {
    "F4SE/Plugins/FreezeSentryF4.dll": "FreezeSentryF4.dll",
    "F4SE/Plugins/FreezeSentryF4Watch.exe": "FreezeSentryF4Watch.exe",
}


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", required=True, help="CMake build directory")
    parser.add_argument("--package", required=True, help="Package directory or zip")
    parser.add_argument("--src", default=Path(__file__).resolve().parent.parent,
                        help="Repository root (for src/plugin.cpp and dist INI)")
    args = parser.parse_args()
    failures, warnings = [], []

    package = Path(args.package)
    if package.is_file() and zipfile.is_zipfile(package):
        expanded = Path(tempfile.mkdtemp(prefix="fs4-release-"))
        with zipfile.ZipFile(package) as archive:
            archive.extractall(expanded)
        # A zip may wrap everything in one top-level folder.
        inner = [child for child in expanded.iterdir() if child.is_dir()]
        package = inner[0] if len(inner) == 1 and not (expanded / "F4SE").exists() else expanded
    if not package.is_dir():
        print(f"FAIL: package is not a directory or zip: {args.package}")
        return 1

    for name in REQUIRED:
        if not (package / name).is_file():
            failures.append(f"missing required file: {name}")
    for name in PDBS:
        if not (package / name).is_file():
            warnings.append(f"missing debug symbols: {name}")

    build = Path(args.build)
    for package_name, build_name in BUILD_BINARIES.items():
        package_file, build_file = package / package_name, build / build_name
        if not build_file.is_file():
            failures.append(f"missing build output: {build_file}")
        elif package_file.is_file() and sha256(package_file) != sha256(build_file):
            failures.append(f"stale binary: {package_name} differs from build output")

    plugin = Path(args.src) / "src" / "plugin.cpp"
    dist_ini = Path(args.src) / "dist" / "F4SE" / "Plugins" / "FreezeSentryF4.ini"
    if plugin.is_file() and dist_ini.is_file():
        keys = set(re.findall(r'setting\s*\(\s*ini\s*,\s*L"([^"]+)"', plugin.read_text()))
        documented = set(re.findall(r"^([A-Za-z0-9]+)\s*=", dist_ini.read_text(), re.M))
        for key in sorted(keys - documented):
            failures.append(f"INI key read by plugin.cpp but undocumented in dist INI: {key}")
    else:
        warnings.append("skipped INI/code drift check (plugin.cpp or dist INI absent)")

    for warning in warnings:
        print(f"WARN: {warning}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(f"PASS: release gate ({len(REQUIRED)} files, hashes match, INI documents code keys)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
