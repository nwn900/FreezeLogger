import contextlib
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_release


class ReleaseVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.build = self.root / "build"
        output = self.build / "RelWithDebInfo"
        output.mkdir(parents=True)
        (output / "FreezeSentryF4.dll").write_bytes(b"plugin")
        (output / "FreezeSentryF4Watch.exe").write_bytes(b"watcher")
        self.source = self.root / "source"
        (self.source / "src").mkdir(parents=True)
        (self.source / "dist/F4SE/Plugins").mkdir(parents=True)
        (self.source / "src/plugin.cpp").write_text('setting(ini, L"TimeoutSeconds")', encoding="utf-8")
        self.ini = b"[FreezeSentryF4]\nTimeoutSeconds=15\n"
        (self.source / "dist/F4SE/Plugins/FreezeSentryF4.ini").write_bytes(self.ini)

    def tearDown(self):
        self.temporary.cleanup()

    def verify(self, package):
        arguments = ["verify_release", "--build", str(self.build), "--config", "RelWithDebInfo",
                     "--package", str(package), "--src", str(self.source)]
        with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(io.StringIO()):
            return verify_release.main()

    def write_zip(self, path, entries):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in entries.items():
                archive.writestr(name, content)

    def test_accepts_canonical_root(self):
        package = self.root / "canonical.zip"
        self.write_zip(package, {
            "F4SE/Plugins/FreezeSentryF4.dll": b"plugin",
            "F4SE/Plugins/FreezeSentryF4Watch.exe": b"watcher",
            "F4SE/Plugins/FreezeSentryF4.ini": self.ini,
        })
        self.assertEqual(self.verify(package), 0)

    def test_rejects_required_files_split_across_zip_roots(self):
        package = self.root / "split.zip"
        self.write_zip(package, {
            "piece0/F4SE/Plugins/FreezeSentryF4.dll": b"plugin",
            "piece1/F4SE/Plugins/FreezeSentryF4Watch.exe": b"watcher",
            "piece2/F4SE/Plugins/FreezeSentryF4.ini": self.ini,
        })
        self.assertEqual(self.verify(package), 1)


if __name__ == "__main__":
    unittest.main()
