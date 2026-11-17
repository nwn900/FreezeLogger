import contextlib
import io
import os
import struct
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import package
import verify_release


def make_pdb(guid, age):
    block_size = 512
    block_count = 4
    info = struct.pack("<III16s", 20000404, 0, age, guid)
    directory = struct.pack("<III", 2, 0xFFFFFFFF, len(info)) + struct.pack("<I", 3)
    data = bytearray(block_size * block_count)
    data[:32] = verify_release.MSF7_MAGIC
    struct.pack_into("<6I", data, 32, block_size, 1, block_count, len(directory), 0, 2)
    data[block_size:block_size + len(directory)] = directory
    struct.pack_into("<I", data, block_size * 2, 1)
    data[block_size * 3:block_size * 3 + len(info)] = info
    return bytes(data)


def make_pe(guid, age, pdb_name):
    data = bytearray(0x300)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112 + 6 * 8, 0x1000, 28)
    section = optional + 0xF0
    data[section:section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x100, 0x200)
    codeview = b"RSDS" + guid + struct.pack("<I", age) + pdb_name.encode("ascii") + b"\0"
    struct.pack_into("<IIHHIIII", data, 0x200, 0, 0, 0, 0, 2, len(codeview), 0x1020, 0x220)
    data[0x220:0x220 + len(codeview)] = codeview
    return bytes(data)


class ReleaseVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.build = self.root / "build"
        output = self.build / "RelWithDebInfo"
        output.mkdir(parents=True)
        self.plugin_guid = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.watch_guid = bytes.fromhex("ffeeddccbbaa99887766554433221100")
        self.plugin_age = 3
        self.watch_age = 4
        self.plugin_binary = make_pe(self.plugin_guid, self.plugin_age, "FreezeSentryF4.pdb")
        self.watch_binary = make_pe(self.watch_guid, self.watch_age, "FreezeSentryF4Watch.pdb")
        self.plugin_pdb = make_pdb(self.plugin_guid, self.plugin_age)
        self.watch_pdb = make_pdb(self.watch_guid, self.watch_age)
        (output / "FreezeSentryF4.dll").write_bytes(self.plugin_binary)
        (output / "FreezeSentryF4Watch.exe").write_bytes(self.watch_binary)
        (output / "FreezeSentryF4.pdb").write_bytes(self.plugin_pdb)
        (output / "FreezeSentryF4Watch.pdb").write_bytes(self.watch_pdb)
        self.source = self.root / "source"
        (self.source / "src").mkdir(parents=True)
        (self.source / "dist/F4SE/Plugins").mkdir(parents=True)
        (self.source / "src/plugin.cpp").write_text('setting(ini, L"TimeoutSeconds")', encoding="utf-8")
        self.ini = b"[FreezeSentryF4]\nTimeoutSeconds=15\n"
        (self.source / "dist/F4SE/Plugins/FreezeSentryF4.ini").write_bytes(self.ini)

    def tearDown(self):
        self.temporary.cleanup()

    def verify(self, package, symbols_mode="required"):
        arguments = ["verify_release", "--build", str(self.build), "--config", "RelWithDebInfo",
                     "--package", str(package), "--src", str(self.source),
                     "--symbols-mode", symbols_mode]
        with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(io.StringIO()):
            return verify_release.main()

    def write_zip(self, path, entries):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in entries.items():
                archive.writestr(name, content)

    def release_entries(self, include_symbols=True):
        entries = {
            "F4SE/Plugins/FreezeSentryF4.dll": self.plugin_binary,
            "F4SE/Plugins/FreezeSentryF4Watch.exe": self.watch_binary,
            "F4SE/Plugins/FreezeSentryF4.ini": self.ini,
        }
        if include_symbols:
            entries["F4SE/Plugins/FreezeSentryF4.pdb"] = self.plugin_pdb
            entries["F4SE/Plugins/FreezeSentryF4Watch.pdb"] = self.watch_pdb
        return entries

    def test_accepts_canonical_root_with_matching_pdbs(self):
        package = self.root / "canonical.zip"
        self.write_zip(package, self.release_entries())
        self.assertEqual(self.verify(package), 0)

    def test_rejects_missing_pdbs_by_default(self):
        package = self.root / "missing-symbols.zip"
        self.write_zip(package, self.release_entries(include_symbols=False))
        self.assertEqual(self.verify(package), 1)

    def test_accepts_symbols_free_package_only_when_declared(self):
        package = self.root / "symbols-free.zip"
        self.write_zip(package, self.release_entries(include_symbols=False))
        self.assertEqual(self.verify(package, symbols_mode="none"), 0)

    def test_rejects_pdbs_in_symbols_free_package(self):
        package = self.root / "unexpected-symbols.zip"
        self.write_zip(package, self.release_entries())
        self.assertEqual(self.verify(package, symbols_mode="none"), 1)

    def test_symbols_free_mode_ignores_directory_named_pdb(self):
        package = self.root / "pdb-directory.zip"
        with zipfile.ZipFile(package, "w") as archive:
            for name, content in self.release_entries(include_symbols=False).items():
                archive.writestr(name, content)
            archive.writestr("optional.pdb/", "")
        self.assertEqual(self.verify(package, symbols_mode="none"), 0)

    def test_rejects_pdb_identity_that_does_not_match_built_binary(self):
        wrong_pdb = make_pdb(b"X" * 16, self.plugin_age)
        (self.build / "RelWithDebInfo/FreezeSentryF4.pdb").write_bytes(wrong_pdb)
        entries = self.release_entries()
        entries["F4SE/Plugins/FreezeSentryF4.pdb"] = wrong_pdb
        package = self.root / "wrong-identity.zip"
        self.write_zip(package, entries)
        self.assertEqual(self.verify(package), 1)

    def test_rejects_packaged_pdb_different_from_build_output(self):
        entries = self.release_entries()
        entries["F4SE/Plugins/FreezeSentryF4.pdb"] = make_pdb(b"X" * 16, self.plugin_age)
        package = self.root / "stale-symbols.zip"
        self.write_zip(package, entries)
        self.assertEqual(self.verify(package), 1)

    def test_rejects_required_files_split_across_zip_roots(self):
        package = self.root / "split.zip"
        self.write_zip(package, {
            "piece0/F4SE/Plugins/FreezeSentryF4.dll": self.plugin_binary,
            "piece1/F4SE/Plugins/FreezeSentryF4Watch.exe": self.watch_binary,
            "piece2/F4SE/Plugins/FreezeSentryF4.ini": self.ini,
            "piece3/F4SE/Plugins/FreezeSentryF4.pdb": self.plugin_pdb,
            "piece4/F4SE/Plugins/FreezeSentryF4Watch.pdb": self.watch_pdb,
        })
        self.assertEqual(self.verify(package), 1)


class PackageSkipPolicyTests(unittest.TestCase):
    def test_layout_only_skip_is_accepted(self):
        accepted, rejected = package.classify_skips(
            [{"test": "layout-rows", "evidence": "SKIP: no executable matches a shipped row digest"}])
        self.assertEqual([entry["test"] for entry in accepted], ["layout-rows"])
        self.assertEqual(rejected, [])
        self.assertIn("policy", accepted[0])
        self.assertFalse(package.qualification(accepted)["runtime_layout_qualified"])
        self.assertTrue(package.qualification(accepted)["etw_available"])

    def test_combined_etw_and_layout_skip_is_accepted(self):
        accepted, rejected = package.classify_skips([
            {"test": "real-dxgi-etw", "evidence": "ETW unavailable"},
            {"test": "layout-rows", "evidence": "SKIP: no executable matches a shipped row digest"},
        ])
        self.assertEqual(len(accepted), 2)
        self.assertEqual(rejected, [])
        self.assertEqual(package.qualification(accepted),
                         {"runtime_layout_qualified": False, "etw_available": False,
                          "pss_clone_qualified": True})

    def test_unexpected_skip_is_rejected(self):
        accepted, rejected = package.classify_skips([{"test": "engine-context", "evidence": "skipped"}])
        self.assertEqual(accepted, [])
        self.assertEqual([entry["test"] for entry in rejected], ["engine-context"])

    def test_duplicate_skip_entries_are_still_classified(self):
        accepted, rejected = package.classify_skips([
            {"test": "layout-rows", "evidence": "a"},
            {"test": "layout-rows", "evidence": "b"},
            {"test": "diagnostics", "evidence": "c"},
        ])
        self.assertEqual(len(accepted), 2)
        self.assertEqual([entry["test"] for entry in rejected], ["diagnostics"])

    def test_snapshot_only_skip_is_accepted(self):
        accepted, rejected = package.classify_skips(
            [{"test": "snapshot-cleanup", "evidence": "SKIP: self snapshot unavailable"}])
        self.assertEqual([entry["test"] for entry in accepted], ["snapshot-cleanup"])
        self.assertEqual(rejected, [])
        self.assertFalse(package.qualification(accepted)["pss_clone_qualified"])
        self.assertTrue(package.qualification(accepted)["runtime_layout_qualified"])

    def test_combined_expected_skips_are_accepted(self):
        accepted, rejected = package.classify_skips([
            {"test": "real-dxgi-etw", "evidence": "ETW unavailable"},
            {"test": "layout-rows", "evidence": "SKIP: no executable"},
            {"test": "snapshot-cleanup", "evidence": "SKIP: self snapshot unavailable"},
        ])
        self.assertEqual(len(accepted), 3)
        self.assertEqual(rejected, [])
        self.assertEqual(package.qualification(accepted),
                         {"runtime_layout_qualified": False, "etw_available": False,
                          "pss_clone_qualified": False})


class PackageReceiptFreshnessTests(unittest.TestCase):
    def test_stale_receipt_detects_newer_test_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "receipt.xml"
            report.write_text("<testsuite/>", encoding="utf-8")
            old = time.time() - 100
            os.utime(report, (old, old))
            exe = root / "FreezeSentryF4ExceptionTests.exe"
            exe.write_bytes(b"MZ")
            os.utime(exe, (old, old))
            self.assertIsNone(package.stale_receipt(report, [exe]))
            newer = time.time() + 100
            os.utime(exe, (newer, newer))
            self.assertEqual(package.stale_receipt(report, [exe]), exe)

    def test_test_inputs_cover_independent_executables_and_scripts(self):
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            output = build / "RelWithDebInfo"
            output.mkdir()
            (output / "FreezeSentryF4ExceptionTests.exe").write_bytes(b"MZ")
            (output / "FreezeSentryF4.dll").write_bytes(b"MZ")
            inputs = package.test_inputs(build, "RelWithDebInfo")
            names = {path.name for path in inputs}
            self.assertIn("FreezeSentryF4ExceptionTests.exe", names)
            self.assertIn("FreezeSentryF4.dll", names)
            self.assertIn("CMakeLists.txt", names)
            self.assertTrue(any(path.suffix == ".py" for path in inputs))


class PackageProvenanceTests(unittest.TestCase):
    def test_source_manifest_reports_commit_and_dirty_state(self):
        manifest = package.source_manifest()
        self.assertIn("commit", manifest)
        self.assertNotEqual(manifest["commit"], "")
        self.assertIn("dirty", manifest)

    def test_test_inputs_include_cpp_sources_and_headers(self):
        inputs = package.test_inputs(Path("."), "RelWithDebInfo")
        names = {path.name for path in inputs}
        self.assertIn("plugin.cpp", names)
        self.assertIn("frames.hpp", names)

    def test_untracked_packaged_file_marks_dirty(self):
        status = "?? src/new.cpp\n?? .cursor/state.json\n M tests/test.cpp\n?? docs/notes.md\n"
        lines = package.packaged_status_lines(status)
        self.assertIn("?? src/new.cpp", lines)
        self.assertIn(" M tests/test.cpp", lines)
        self.assertIn("?? docs/notes.md", lines)
        self.assertNotIn("?? .cursor/state.json", lines)

    def test_archive_manifest_digest_is_stable(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "source.zip"
            with zipfile.ZipFile(archive, "w") as source:
                source.writestr("a.txt", "a")
                source.writestr("b.txt", "b")
            first = package.archive_manifest_digest(archive)
            second = package.archive_manifest_digest(archive)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 64)


if __name__ == "__main__":
    unittest.main()
