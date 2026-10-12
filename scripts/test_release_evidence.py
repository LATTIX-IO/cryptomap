"""Adversarial and regression tests for release evidence inspection."""
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from release_evidence import MAX_ARCHIVE, MAX_ENTRIES, inspect

SHA = "a" * 40
ROOT = "cryptomap-0.1.0"
MANIFEST = b'[package]\nname="cryptomap"\nversion="0.1.0"\npublish=false\n'


def archive_at(path: Path, changes=None):
    """Build a synthetic release archive with replaceable fixture members."""
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
        """Create an isolated archive path for each adversarial case."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "cryptomap-0.1.0.crate"

    def test_deterministic_valid_package(self):
        """Identical archive bytes and commit yield identical evidence."""
        archive_at(self.path)
        a = inspect(self.path, SHA)
        b = inspect(self.path, SHA)
        self.assertEqual(a, b)
        self.assertEqual(a["version"], "0.1.0")
        self.assertEqual(len(a["sha256"]), 64)
        self.assertFalse(a["publish_enabled"])
        self.assertEqual(len(a["files"]), 4)

    def test_reject_enabled_publication(self):
        """Fail prepublication evidence when publication is enabled."""
        archive_at(self.path, {"Cargo.toml": MANIFEST.replace(b"false", b"true")})
        with self.assertRaisesRegex(ValueError, "premature"):
            inspect(self.path, SHA)

    def test_reject_secret_filename(self):
        """Reject known high-risk secret-bearing filenames."""
        archive_at(self.path, {"secrets/.env.production": b"secret"})
        with self.assertRaises(ValueError):
            inspect(self.path, SHA)

    def test_reject_path_traversal(self):
        """Prevent parent-directory references in archive entries."""
        archive_at(self.path)
        with tarfile.open(self.path, "w:gz") as archive:
            info = tarfile.TarInfo(f"{ROOT}/../escape")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(ValueError):
            inspect(self.path, SHA)

    def test_reject_symlink(self):
        """Reject symbolic links rather than following their targets."""
        with tarfile.open(self.path, "w:gz") as archive:
            info = tarfile.TarInfo(f"{ROOT}/redirect")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../outside"
            archive.addfile(info)
        with self.assertRaises(ValueError):
            inspect(self.path, SHA)

    def test_reject_duplicate_archive_entry(self):
        """Prevent duplicate regular-file paths from being accepted."""
        archive_at(self.path)
        # Duplicate members must not be treated as an unambiguous release.
        with tarfile.open(self.path, "w:gz") as archive:
            for body in (b"first", b"second"):
                info = tarfile.TarInfo(f"{ROOT}/README.md")
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        with self.assertRaises(ValueError):
            inspect(self.path, SHA)

    def test_reject_directory_file_collision_in_either_order(self):
        """Reject file-directory collisions independent of tar member order."""
        for directory_first in (True, False):
            with tarfile.open(self.path, "w:gz") as archive:
                directory = tarfile.TarInfo(f"{ROOT}/collide/")
                directory.type = tarfile.DIRTYPE
                regular = tarfile.TarInfo(f"{ROOT}/collide")
                regular.size = 1
                for entry in ([directory, regular] if directory_first else [regular, directory]):
                    if entry.isfile():
                        archive.addfile(entry, io.BytesIO(b"x"))
                    else:
                        archive.addfile(entry)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                inspect(self.path, SHA)

    def test_reject_file_used_as_parent(self):
        """Reject a regular file followed by an overlapping child path."""
        with tarfile.open(self.path, "w:gz") as archive:
            for name in ("parent", "parent/child"):
                info = tarfile.TarInfo(f"{ROOT}/{name}")
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
        with self.assertRaisesRegex(ValueError, "overlapping"):
            inspect(self.path, SHA)

    def test_reject_too_many_entries_without_eager_materialization(self):
        """Reject member-count overflow during streaming header inspection."""
        with tarfile.open(self.path, "w:gz") as archive:
            for i in range(MAX_ENTRIES + 1):
                info = tarfile.TarInfo(f"{ROOT}/entry-{i:05d}")
                info.size = 0
                archive.addfile(info, io.BytesIO())
        with self.assertRaisesRegex(ValueError, "member budget"):
            inspect(self.path, SHA)

    def test_reject_compressed_oversized_member_before_reading(self):
        """Reject a compressed oversized member from its declared length."""
        with tarfile.open(self.path, "w:gz") as archive:
            info = tarfile.TarInfo(f"{ROOT}/oversized")
            info.size = MAX_ARCHIVE + 1
            archive.addfile(info, io.BytesIO(b"\x00" * (MAX_ARCHIVE + 1)))
        with self.assertRaisesRegex(ValueError, "expanded archive budget"):
            inspect(self.path, SHA)

    def test_reject_ambiguous_normalized_paths(self):
        """Reject entries whose raw path is not already canonical."""
        for path in (f"{ROOT}//name", f"{ROOT}/./name"):
            with tarfile.open(self.path, "w:gz") as archive:
                info = tarfile.TarInfo(path)
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            with self.assertRaisesRegex(ValueError, "unsafe archive"):
                inspect(self.path, SHA)

    def test_reject_wrong_commit(self):
        """Require a full source commit in release evidence."""
        archive_at(self.path)
        with self.assertRaises(ValueError):
            inspect(self.path, "not-a-sha")


if __name__ == "__main__":
    unittest.main()
