"""Adversarial and regression tests for release evidence inspection."""
import gzip
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from release_evidence import MAX_ARCHIVE, MAX_ENTRIES, MAX_TAR_STREAM, inspect

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

    def test_reject_required_readme_or_license_as_directory(self):
        """Required documentation and licenses must be actual regular files."""
        for missing in ("README.md", "LICENSE-MIT", "LICENSE-APACHE"):
            with tarfile.open(self.path, "w:gz") as archive:
                for rel, data in (
                    ("Cargo.toml", MANIFEST),
                    ("README.md", b"readme"),
                    ("LICENSE-MIT", b"MIT"),
                    ("LICENSE-APACHE", b"Apache"),
                ):
                    name = f"{ROOT}/{rel}"
                    info = tarfile.TarInfo(name)
                    if rel == missing:
                        info.type = tarfile.DIRTYPE
                        archive.addfile(info)
                    else:
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
            with self.assertRaisesRegex(ValueError, "missing release-critical"):
                inspect(self.path, SHA)

    def test_reject_large_pax_header_before_tarfile_materialization(self):
        """Cap PAX metadata decompression even before the first member yields."""
        with tarfile.open(self.path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo(f"{ROOT}/file")
            info.pax_headers = {"comment": "A" * (MAX_TAR_STREAM + 1)}
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        self.assertLess(self.path.stat().st_size, MAX_ARCHIVE)
        with self.assertRaisesRegex(ValueError, "decompressed tar stream budget"):
            inspect(self.path, SHA)

    def test_reject_invalid_header_after_valid_required_entries(self):
        """Do not treat a corrupted noninitial tar header as valid EOF."""
        archive_at(self.path)
        with gzip.open(self.path, "rb") as stream:
            data = bytearray(stream.read())
        with tarfile.open(self.path, "r:gz") as tar:
            last_end = max(member.offset_data + ((member.size + 511) // 512) * 512 for member in tar)
        # Inject a 512-byte nonzero header with a deliberately invalid checksum
        # at the first EOF marker; tarfile would otherwise silently stop here.
        data[last_end:last_end + 512] = b"A" * 512
        with gzip.open(self.path, "wb") as stream:
            stream.write(data)
        with self.assertRaisesRegex(ValueError, "canonical tar terminator"):
            inspect(self.path, SHA)

    def test_reject_truncated_eof_padding_after_valid_files(self):
        """A single or missing zero block cannot certify a complete crate."""
        archive_at(self.path)
        with gzip.open(self.path, "rb") as stream:
            data = stream.read()
        with tarfile.open(self.path, "r:gz") as tar:
            end = max(member.offset_data + ((member.size + 511) // 512) * 512 for member in tar)
        with gzip.open(self.path, "wb") as stream:
            stream.write(data[:end + 512])
        with self.assertRaisesRegex(ValueError, "canonical tar terminator"):
            inspect(self.path, SHA)

    def test_reject_wrong_commit(self):
        """Require a full source commit in release evidence."""
        archive_at(self.path)
        with self.assertRaises(ValueError):
            inspect(self.path, "not-a-sha")


if __name__ == "__main__":
    unittest.main()
