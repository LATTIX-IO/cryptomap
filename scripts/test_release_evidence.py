"""Adversarial and regression tests for release evidence inspection."""
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from release_evidence import inspect

SHA = "a" * 40
ROOT = "cryptomap-0.1.0"
MANIFEST = b'[package]\nname="cryptomap"\nversion="0.1.0"\npublish=false\n'


def archive_at(path: Path, changes=None):
    entries = {
        "Cargo.toml": MANIFEST,
        "README.md": b"readme",
        "LICENSE-MIT": b"MIT",
        "LICENSE-APACHE": b"Apache",
    }
    entries.update(changes or {})
    with tarfile.open(path, "w:gz") as archive:
        for rel, data in entries.items():
            info = tarfile.TarInfo(f"{ROOT}/{rel}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "cryptomap-0.1.0.crate"

    def test_deterministic_valid_package(self):
        archive_at(self.path)
        a = inspect(self.path, SHA)
        b = inspect(self.path, SHA)
        self.assertEqual(a, b)
        self.assertEqual(a["version"], "0.1.0")
        self.assertEqual(len(a["sha256"]), 64)
        self.assertFalse(a["publish_enabled"])
        self.assertEqual(len(a["files"]), 4)

    def test_reject_enabled_publication(self):
        archive_at(self.path, {"Cargo.toml": MANIFEST.replace(b"false", b"true")})
        with self.assertRaisesRegex(ValueError, "premature"):
            inspect(self.path, SHA)

    def test_reject_secret_filename(self):
        archive_at(self.path, {"secrets/.env.production": b"secret"})
        with self.assertRaises(ValueError):
            inspect(self.path, SHA)

    def test_reject_path_traversal(self):
        archive_at(self.path)
        with tarfile.open(self.path, "w:gz") as archive:
            info = tarfile.TarInfo(f"{ROOT}/../escape")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(ValueError):
            inspect(self.path, SHA)

    def test_reject_symlink(self):
        archive_at(self.path)
        with tarfile.open(self.path, "a") as archive:
            info = tarfile.TarInfo(f"{ROOT}/redirect")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../outside"
            archive.addfile(info)
        with self.assertRaises(ValueError):
            inspect(self.path, SHA)

    def test_reject_duplicate_archive_entry(self):
        archive_at(self.path)
        # Duplicate members must not be treated as an unambiguous release.
        with tarfile.open(self.path, "w:gz") as archive:
            for body in (b"first", b"second"):
                info = tarfile.TarInfo(f"{ROOT}/README.md")
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        with self.assertRaises(ValueError):
            inspect(self.path, SHA)

    def test_reject_wrong_commit(self):
        archive_at(self.path)
        with self.assertRaises(ValueError):
            inspect(self.path, "not-a-sha")


if __name__ == "__main__":
    unittest.main()
