#!/usr/bin/env python3
"""Verify that a release directory or ZIP contains the built binaries and INI."""
import argparse
import hashlib
import re
import sys
import zipfile
from pathlib import Path


REQUIRED = (
    "F4SE/Plugins/FreezeSentryF4.dll",
    "F4SE/Plugins/FreezeSentryF4Watch.exe",
    "F4SE/Plugins/FreezeSentryF4.ini",
)
PDBS = (
    "F4SE/Plugins/FreezeSentryF4.pdb",
    "F4SE/Plugins/FreezeSentryF4Watch.pdb",
)
BUILD_BINARIES = {
    "F4SE/Plugins/FreezeSentryF4.dll": "FreezeSentryF4.dll",
    "F4SE/Plugins/FreezeSentryF4Watch.exe": "FreezeSentryF4Watch.exe",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_file(build: Path, name: str, config: str) -> Path:
    for candidate in (build / name, build / config / name):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"missing build output: {name} under {build}")


def package_reader(package: Path):
    if package.is_dir():
        def read(name: str) -> bytes:
            return (package / Path(*name.split("/"))).read_bytes()

        def exists(name: str) -> bool:
            return (package / Path(*name.split("/"))).is_file()

        return read, exists
    if not package.is_file() or not zipfile.is_zipfile(package):
        raise FileNotFoundError(f"package is not a directory or ZIP: {package}")
    archive = zipfile.ZipFile(package)
    names = archive.namelist()

    def member(name: str) -> str:
        matches = [entry for entry in names if entry == name or entry.endswith("/" + name)]
        if len(matches) != 1:
            raise FileNotFoundError(f"expected one packaged entry {name}, found {len(matches)}")
        return matches[0]

    def read(name: str) -> bytes:
        return archive.read(member(name))

    def exists(name: str) -> bool:
        try:
            member(name)
            return True
        except FileNotFoundError:
            return False

    return read, exists


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", required=True, type=Path, help="CMake build directory")
    parser.add_argument("--package", required=True, type=Path, help="Package directory or ZIP")
    parser.add_argument("--config", default="Release", help="CMake configuration")
    parser.add_argument("--src", default=Path(__file__).resolve().parent.parent,
                        type=Path, help="Repository root")
    args = parser.parse_args()
    failures, warnings = [], []
    package = args.package.resolve()
    read, exists = package_reader(package)

    for name in REQUIRED:
        if not exists(name):
            failures.append(f"missing required file: {name}")
    for name in PDBS:
        if not exists(name):
            warnings.append(f"missing debug symbols: {name}")

    build = args.build.resolve()
    for packaged_name, build_name in BUILD_BINARIES.items():
        try:
            built = build_file(build, build_name, args.config).read_bytes()
            if exists(packaged_name) and sha256(read(packaged_name)) != sha256(built):
                failures.append(f"stale binary: {packaged_name} differs from build output")
        except FileNotFoundError as error:
            failures.append(str(error))

    source = args.src.resolve()
    plugin = source / "src/plugin.cpp"
    dist_ini = source / "dist/F4SE/Plugins/FreezeSentryF4.ini"
    packaged_ini_name = "F4SE/Plugins/FreezeSentryF4.ini"
    if plugin.is_file() and dist_ini.is_file() and exists(packaged_ini_name):
        packaged_ini = read(packaged_ini_name)
        expected_ini = dist_ini.read_bytes()
        if packaged_ini != expected_ini:
            failures.append("packaged INI differs from canonical dist INI")
        try:
            ini_text = packaged_ini.decode("utf-8-sig")
        except UnicodeDecodeError:
            failures.append("packaged INI is not valid UTF-8")
            ini_text = ""
        keys = set(re.findall(r'setting\s*\(\s*ini\s*,\s*L"([^"]+)"',
                              plugin.read_text(encoding="utf-8")))
        documented = set(re.findall(r"^([A-Za-z0-9]+)\s*=", ini_text, re.M))
        for key in sorted(keys - documented):
            failures.append(f"INI key read by plugin.cpp but absent from packaged INI: {key}")
    else:
        failures.append("cannot verify the packaged INI against code and canonical dist INI")

    for warning in warnings:
        print(f"WARN: {warning}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(f"PASS: release gate ({len(REQUIRED)} packaged files, build hashes and packaged INI verified)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
