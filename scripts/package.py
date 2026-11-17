"""Package a validated local build without publishing or deploying it."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[1]
VERSION = re.search(
    r"project\(FreezeSentryF4 VERSION ([0-9.]+)",
    (ROOT / "CMakeLists.txt").read_text(encoding="utf-8"),
).group(1)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def required(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


# Environment-dependent skips that are documented and acceptable on a clean
# host. A skipped mandatory test is not a pass: every entry here is reported in
# the release receipt as "not qualified on this machine".
SKIP_POLICY = {
    "real-dxgi-etw": "DXGI real-time ETW session unavailable on this host",
    "layout-rows": "no installed Fallout 4 executable matched a shipped layout row",
    "snapshot-cleanup": "self PSS clone unavailable on this host",
}


def classify_skips(skipped: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split receipt skips into documented environment skips and failures."""
    accepted, rejected = [], []
    for entry in skipped:
        reason = SKIP_POLICY.get(entry["test"])
        if reason is None:
            rejected.append(entry)
        else:
            accepted.append({**entry, "policy": reason})
    return accepted, rejected


def qualification(accepted_skips: list[dict]) -> dict:
    """Report which environment-dependent checks did not run on this host."""
    names = {entry["test"] for entry in accepted_skips}
    return {
        "runtime_layout_qualified": "layout-rows" not in names,
        "etw_available": "real-dxgi-etw" not in names,
        "pss_clone_qualified": "snapshot-cleanup" not in names,
    }


def test_inputs(build: Path, config: str) -> list[Path]:
    """Every file whose change invalidates a test receipt."""
    inputs = []
    for directory in (build, build / config):
        if directory.is_dir():
            inputs.extend(path for path in directory.glob("*.exe") if path.is_file())
            inputs.extend(path for path in directory.glob("*.dll") if path.is_file())
    inputs.append(ROOT / "CMakeLists.txt")
    inputs.extend(path for path in (ROOT / "tests").rglob("*.py") if path.is_file())
    for directory in ("src", "fuzz"):
        inputs.extend(path for path in (ROOT / directory).rglob("*") if path.is_file())
    return inputs


def build_configuration(build: Path, config: str) -> None:
    """Rebuild the chosen configuration so binaries match the current source."""
    subprocess.run(["cmake", "--build", str(build), "--config", config, "--parallel"], check=True)


PACKAGED_DIRECTORIES = ("src", "tests", "docs", "dist", "scripts", "fuzz", "tools")
PACKAGED_ROOT_FILES = (".gitignore", "CMakeLists.txt", "README.md", "LICENSE")


def packaged_status_lines(status: str) -> list[str]:
    """Porcelain lines for files that would enter the source archive."""
    lines = []
    for line in status.splitlines():
        if len(line) < 4:
            continue
        path = line[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        if path in PACKAGED_ROOT_FILES or path.split("/", 1)[0] in PACKAGED_DIRECTORIES:
            lines.append(line)
    return lines


def source_manifest() -> dict:
    """Immutable source revision and dirty state for the release receipt.

    Untracked files under packaged directories are included: the source archive
    is built with rglob, so a clean HEAD alone would misrepresent the archive.
    """
    def git(*arguments: str) -> str:
        return subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout
    try:
        commit = git("rev-parse", "HEAD").strip()
        packaged = packaged_status_lines(git("status", "--porcelain"))
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {"commit": "unavailable", "dirty": None, "dirty_paths": []}
    return {"commit": commit, "dirty": bool(packaged), "dirty_paths": packaged[:20]}


def archive_manifest_digest(archive: Path) -> str:
    """Digest of the complete source archive manifest (path + content hash)."""
    with zipfile.ZipFile(archive) as source:
        lines = [f"{hashlib.sha256(source.read(name)).hexdigest()}  {name}"
                 for name in sorted(source.namelist())]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def stale_receipt(report: Path, inputs: list[Path]) -> Path | None:
    """Return the newest input that is newer than the receipt, if any."""
    newest = None
    for path in inputs:
        if not path.is_file():
            continue
        if path.stat().st_mtime > report.stat().st_mtime + 1:
            if newest is None or path.stat().st_mtime > newest.stat().st_mtime:
                newest = path
    return newest


def rerun_tests(build: Path, config: str) -> Path:
    """Run the registered suite and return a fresh JUnit receipt."""
    receipt = build / "packaging-receipt.xml"
    receipt.unlink(missing_ok=True)
    subprocess.run(["ctest", "--test-dir", str(build), "-C", config,
                    "--output-junit", str(receipt)], check=True)
    required(receipt.is_file(), "CTest did not produce a JUnit receipt")
    return receipt


def build_artifact(build: Path, name: str, config: str) -> Path:
    candidates = [build / name, build / config / name]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError(f"missing build output {name} under {build}")


def build_source_archive(archive_path: Path, build: Path, config: str, symbols_mode: str) -> None:
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8", errors="replace")
    generator = re.search(r"^CMAKE_GENERATOR:INTERNAL=(.+)$", cache, re.M)
    platform = re.search(r"^CMAKE_GENERATOR_PLATFORM:INTERNAL=(.*)$", cache, re.M)
    required(generator is not None, f"cannot read CMake generator from {build / 'CMakeCache.txt'}")
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        for name in names:
            member = PurePosixPath(name)
            required(not member.is_absolute() and ".." not in member.parts and "\\" not in name,
                     f"unsafe source archive path: {name}")
        required("CMakeLists.txt" in names and "fuzz/fuzz_buffout_parser.cpp" in names,
                 "source archive omits required root or fuzz source")
        with tempfile.TemporaryDirectory(prefix="fsf4-source-build-") as temporary:
            source_root = Path(temporary) / "source"
            source_root.mkdir()
            archive.extractall(source_root)
            source_build = Path(temporary) / "build"
            command = ["cmake", "-S", str(source_root), "-B", str(source_build), "-G", generator.group(1)]
            if platform and platform.group(1):
                command += ["-A", platform.group(1)]
            command += [f"-DFSF4_SYMBOLS_MODE:STRING={symbols_mode}"]
            subprocess.run(command, check=True)
            subprocess.run(["cmake", "--build", str(source_build), "--config", config, "--parallel"], check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build/audit-baseline")
    parser.add_argument("--config", default="RelWithDebInfo")
    parser.add_argument("--symbols-mode", choices=("required", "none"), default="required",
                        help="package matching PDBs or deliberately create a symbols-free package")
    parser.add_argument("--stage", type=Path, default=ROOT / f"build/package-{VERSION}")
    parser.add_argument("--artifacts", type=Path, default=ROOT / "artifacts")
    parser.add_argument("--test-report", type=Path, default=ROOT / f"build/validation-{VERSION}.xml",
                        help="JUnit XML produced by ctest --output-junit")
    parser.add_argument("--no-rerun-tests", action="store_true",
                        help="trust the supplied receipt instead of rerunning the registered suite")
    args = parser.parse_args()
    build = args.build.resolve()
    stage = args.stage.resolve()
    artifacts = args.artifacts.resolve()
    report = args.test_report.resolve()
    cache = (build / "CMakeCache.txt").read_text(encoding="utf-8", errors="replace")
    configured_symbols = re.search(r"^FSF4_SYMBOLS_MODE:STRING=(required|none)$", cache, re.M)
    required(configured_symbols is not None, f"CMake cache has no valid FSF4_SYMBOLS_MODE: {build / 'CMakeCache.txt'}")
    required(configured_symbols.group(1) == args.symbols_mode,
             f"package symbols mode {args.symbols_mode} differs from CMake mode {configured_symbols.group(1)}")
    generator = re.search(r"^CMAKE_GENERATOR:INTERNAL=(.+)$", cache, re.M)
    home = re.search(r"^CMAKE_HOME_DIRECTORY:INTERNAL=(.+)$", cache, re.M)
    required(home is not None and Path(home.group(1)).resolve() == ROOT.resolve(),
             f"build tree {build} was configured for {home.group(1) if home else 'unknown'}, not {ROOT}")

    # Binaries must be built from the source that is about to be archived: a
    # source edit after the last build must not ship with stale executables.
    build_configuration(build, args.config)

    inventory = subprocess.run(
        ["ctest", "--test-dir", str(build), "-C", args.config, "--show-only=json-v1"],
        check=True, capture_output=True, text=True,
    )
    expected_tests = {item["name"] for item in json.loads(inventory.stdout).get("tests", [])}
    required(bool(expected_tests), "CTest reports no registered tests")
    if args.no_rerun_tests:
        required(report.is_file(), f"missing CTest JUnit report: {report}")
        stale = stale_receipt(report, test_inputs(build, args.config))
        required(stale is None, f"stale CTest receipt: {report} predates {stale}")
    else:
        # A receipt is only provenance if it was produced from the current tree.
        # Rerun the registered suite so an independent test executable or script
        # change cannot be packaged behind an old green receipt.
        report = rerun_tests(build, args.config)
    suite = ET.parse(report).getroot()
    tests = list(suite.iter("testcase"))
    actual_tests = {test.attrib.get("name", "") for test in tests}
    required(len(tests) == len(expected_tests) and actual_tests == expected_tests,
             f"test receipt set differs from CTest inventory: expected={sorted(expected_tests)} actual={sorted(actual_tests)}")
    failed = [test.attrib.get("name", "unnamed") for test in tests
              if test.find("failure") is not None or test.find("error") is not None]
    required(not failed, f"test failures in receipt: {failed}")
    names = [test.attrib.get("name", "") for test in tests]
    required(len(names) == len(set(names)), "duplicate test names in receipt")
    skipped = [{
        "test": test.attrib["name"],
        "evidence": test.findtext("system-out", "").strip() or
                    test.find("skipped").attrib.get("message", ""),
    } for test in tests if test.find("skipped") is not None]
    accepted_skips, rejected_skips = classify_skips(skipped)
    required(not rejected_skips,
             f"undocumented skipped tests: {[entry['test'] for entry in rejected_skips]}")

    dll = build_artifact(build, "FreezeSentryF4.dll", args.config)
    watch = build_artifact(build, "FreezeSentryF4Watch.exe", args.config)
    required(not stage.exists(), f"refusing to replace existing package stage: {stage}")
    required(stage.is_relative_to(ROOT / "build"), "package stage must stay under the repository build directory")
    generated_outputs = []
    try:
        subprocess.run(["cmake", "--install", str(build), "--prefix", str(stage), "--config", args.config], check=True)
        plugin_dir = stage / "F4SE/Plugins"
        required((plugin_dir / "FreezeSentryF4.dll").read_bytes() == dll.read_bytes(), "installed DLL differs from build output")
        required((plugin_dir / "FreezeSentryF4Watch.exe").read_bytes() == watch.read_bytes(), "installed watcher differs from build output")
        required((plugin_dir / "FreezeSentryF4.ini").read_bytes() ==
                 (ROOT / "dist/F4SE/Plugins/FreezeSentryF4.ini").read_bytes(), "installed INI differs from source INI")
        if args.symbols_mode == "required":
            for name in ("FreezeSentryF4.pdb", "FreezeSentryF4Watch.pdb"):
                staged_pdb = plugin_dir / name
                built_pdb = build_artifact(build, name, args.config)
                required(staged_pdb.read_bytes() == built_pdb.read_bytes(), f"installed PDB differs from build output: {name}")
        else:
            required(not any(path.is_file() and path.suffix.lower() == ".pdb" for path in stage.rglob("*")),
                     "symbols-free stage unexpectedly contains PDB files")

        manifest = stage / "FreezeSentryF4/SHA256SUMS.txt"
        payload = sorted(path for path in stage.rglob("*") if path.is_file() and path != manifest)
        manifest.write_text("".join(
            f"{sha256(path)}  {path.relative_to(stage).as_posix()}\n" for path in payload
        ), encoding="utf-8")

        artifacts.mkdir(parents=True, exist_ok=True)
        binary = artifacts / f"FreezeSentryF4-{VERSION}-windows-x64.zip"
        source = artifacts / f"FreezeSentryF4-{VERSION}-source.zip"
        checksums = artifacts / f"SHA256SUMS-{VERSION}.txt"
        receipt_path = artifacts / f"validation-{VERSION}.json"
        for output in (binary, source, checksums, receipt_path):
            required(not output.exists(), f"refusing to replace existing release artifact: {output}")
        generated_outputs = [binary, source, checksums, receipt_path]

        with zipfile.ZipFile(binary, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(stage).as_posix())

        sources = [ROOT / name for name in (".gitignore", "CMakeLists.txt", "README.md", "LICENSE")]
        private_work = ROOT / "docs" / "agent-work"
        for directory in ("src", "tests", "docs", "dist", "scripts", "fuzz", "tools"):
            sources.extend(
                path for path in (ROOT / directory).rglob("*")
                if path.is_file() and "__pycache__" not in path.parts
                and not (directory == "docs" and private_work in path.parents)
            )
        source_files = sorted(set(sources))
        required(all(path.is_file() for path in source_files), "source archive input is missing")
        tools_files = {path.relative_to(ROOT).as_posix() for path in (ROOT / "tools").rglob("*") if path.is_file()}
        required(tools_files <= {path.relative_to(ROOT).as_posix() for path in source_files},
                 "source archive omits repository tools")
        with zipfile.ZipFile(source, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in source_files:
                archive.write(path, path.relative_to(ROOT).as_posix())

        for artifact, source_root in ((binary, stage), (source, ROOT)):
            with zipfile.ZipFile(artifact) as archive:
                required(archive.testzip() is None, f"corrupt archive: {artifact}")
                for name in archive.namelist():
                    member = Path(*Path(name).parts)
                    required((source_root / member).is_file(), f"archive contains unexpected path: {name}")
                    required(archive.read(name) == (source_root / member).read_bytes(), f"archive content mismatch: {name}")

        with zipfile.ZipFile(binary) as archive:
            for line in archive.read("FreezeSentryF4/SHA256SUMS.txt").decode("utf-8").splitlines():
                expected, name = line.split("  ", 1)
                required(hashlib.sha256(archive.read(name)).hexdigest() == expected, f"manifest mismatch: {name}")

        verifier = ROOT / "scripts/verify_release.py"
        for package_path in (stage, binary):
            subprocess.run([
                sys.executable, str(verifier), "--build", str(build), "--config", args.config,
                "--package", str(package_path), "--symbols-mode", args.symbols_mode,
            ], check=True)

        build_source_archive(source, build, args.config, args.symbols_mode)

        checksums.write_text("".join(
            f"{sha256(path)}  {path.name}\n" for path in (binary, source)
        ), encoding="utf-8")
        receipt = {
            "version": VERSION,
            "source": source_manifest(),
            "source_archive_manifest_sha256": archive_manifest_digest(source),
            "build": {
                "generator": generator.group(1) if generator else "unknown",
                "config": args.config,
                "symbols_mode": args.symbols_mode,
            },
            "readiness": "local game-test candidate",
            "tests_registered": len(expected_tests),
            "tests_passed": len(tests) - len(skipped),
            "tests_skipped": accepted_skips,
            **qualification(accepted_skips),
            "symbols_mode": args.symbols_mode,
            "game_startup_qualified": False,
            "gameplay_qualified": False,
            "deployed": False,
            "external_crash_correlation": "metadata and time produce a candidate; corroboration requires an exact in-process exception and loaded-module identity",
            "payloads": [
                {"file": path.name, "bytes": path.stat().st_size, "sha256": sha256(path)}
                for path in (binary, source)
            ],
        }
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(receipt, indent=2))
        return 0
    except Exception:
        for output in generated_outputs:
            output.unlink(missing_ok=True)
        shutil.rmtree(stage, ignore_errors=True)
        raise


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"PACKAGE FAILED: {error}", file=sys.stderr)
        sys.exit(1)
