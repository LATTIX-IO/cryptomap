"""Adversarial SPDX and exact Cargo.lock dependency verification regressions."""
import json
import tempfile
import unittest
from pathlib import Path

from verify_release_sbom import EXPECTED_DIRECT, locked_direct_versions, validate


def sample() -> dict:
    """Build a minimally complete SPDX 2.3 document with locked test versions."""
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "cryptomap-test-dependencies",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.invalid/spdx/cryptomap-test",
        "creationInfo": {
            "created": "2026-10-12T12:00:00Z",
            "creators": ["Tool: Syft"],
        },
        "packages": [
            {
                "SPDXID": f"SPDXRef-crate-{i}",
                "name": name,
                "versionInfo": "1.0.0",
                "downloadLocation": "NOASSERTION",
            }
            for i, name in enumerate(sorted(EXPECTED_DIRECT))
        ],
    }


def lock_fixture() -> str:
    """Provide a structurally representative Cargo.lock v4 with direct packages."""
    header = 'version = 4\n\n[[package]]\nname = "cryptomap"\nversion = "0.1.0"\ndependencies = ['
    entries = ", ".join(f'"{name}"' for name in sorted(EXPECTED_DIRECT))
    packages = [
        f'[[package]]\nname = "{name}"\nversion = "1.0.0"\n'
        for name in sorted(EXPECTED_DIRECT)
    ]
    return header + entries + "]\n\n" + "\n".join(packages)


class SoftwareSbomTests(unittest.TestCase):
    """Fail closed on missing metadata, lockfile drift and invalid identity."""

    def setUp(self):
        """Set up synthetic SPDX plus a separate locked-source fixture."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "software.spdx.json"
        self.lock = Path(self.temp.name) / "Cargo.lock"
        self.lock.write_text(lock_fixture(), encoding="utf-8")

    def write(self, document):
        """Write a JSON object to the SPDX fixture path."""
        self.path.write_text(json.dumps(document), encoding="utf-8")

    def check(self):
        """Verify SPDX against the separately loaded exact lockfile fixture."""
        return validate(self.path, self.lock)

    def test_valid_software_inventory(self):
        """Accept complete SPDX metadata and exactly matching direct versions."""
        self.write(sample())
        result = self.check()
        self.assertEqual(result["spdxVersion"], "SPDX-2.3")
        self.assertEqual(result["package_count"], len(EXPECTED_DIRECT))
        self.assertEqual(result["direct_dependency_versions"], {name: "1.0.0" for name in EXPECTED_DIRECT})

    def test_reject_missing_required_spdx_fields(self):
        """Every required document and package metadata field must be present."""
        for field in ("name", "documentNamespace", "creationInfo", "SPDXID", "dataLicense"):
            doc = sample()
            del doc[field]
            self.write(doc)
            with self.assertRaises(ValueError):
                self.check()
        for field in ("created", "creators"):
            doc = sample()
            del doc["creationInfo"][field]
            self.write(doc)
            with self.assertRaises(ValueError):
                self.check()
        for field in ("name", "SPDXID", "downloadLocation"):
            doc = sample()
            del doc["packages"][0][field]
            self.write(doc)
            with self.assertRaises(ValueError):
                self.check()

    def test_reject_wrong_schema_or_identity(self):
        """Never accept non-SPDX, anonymous or bad timestamp documents."""
        for field, value in [
            ("spdxVersion", "SPDX-2.2"),
            ("SPDXID", "SPDXRef-other"),
            ("dataLicense", "NOASSERTION"),
            ("documentNamespace", ""),
            ("name", " "),
            ("creationInfo", {}),
        ]:
            doc = sample()
            doc[field] = value
            self.write(doc)
            with self.assertRaises(ValueError):
                self.check()
        doc = sample()
        doc["creationInfo"]["created"] = "yesterday"
        self.write(doc)
        with self.assertRaisesRegex(ValueError, "timestamp"):
            self.check()

    def test_reject_missing_or_unversioned_direct_dependency(self):
        """Missing or versionless direct crates invalidate SPDX coverage."""
        document = sample()
        document["packages"].pop()
        self.write(document)
        with self.assertRaisesRegex(ValueError, "missing locked"):
            self.check()
        document = sample()
        document["packages"][0]["versionInfo"] = ""
        self.write(document)
        with self.assertRaisesRegex(ValueError, "unversioned"):
            self.check()

    def test_reject_wrong_nonempty_version(self):
        """A forged but nonempty version must not pass source lock attestation."""
        doc = sample()
        doc["packages"][0]["versionInfo"] = "9.9.9"
        self.write(doc)
        with self.assertRaisesRegex(ValueError, "differs from Cargo.lock"):
            self.check()
        self.lock.write_text(
            lock_fixture().replace(
                'name = "cap-fs-ext"\nversion = "1.0.0"',
                'name = "cap-fs-ext"\nversion = "2.0.0"',
            ),
            encoding="utf-8",
        )
        self.write(sample())
        with self.assertRaisesRegex(ValueError, "differs from Cargo.lock"):
            self.check()

    def test_reject_duplicate_package_identity(self):
        """Reject duplicate SPDX identifiers even when versions are correct."""
        doc = sample()
        doc["packages"][1]["SPDXID"] = doc["packages"][0]["SPDXID"]
        self.write(doc)
        with self.assertRaisesRegex(ValueError, "duplicate package"):
            self.check()

    def test_reject_missing_ambiguous_or_corrupted_lockfile(self):
        """The SBOM cannot pass without unique source-bound root dependencies."""
        self.write(sample())
        self.lock.unlink()
        with self.assertRaisesRegex(ValueError, "reviewed Cargo.lock"):
            self.check()
        self.lock.write_text(lock_fixture().replace('"serde"', '"unknown"', 1), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "direct dependency contract"):
            self.check()
        self.lock.write_text(lock_fixture() + '\n[[package]]\nname = "serde"\nversion = "8.8.8"\n')
        with self.assertRaisesRegex(ValueError, "ambiguous locked version"):
            self.check()


    def test_optional_parser_packages_require_exact_locked_spdx_versions(self):
        """Optional parser crates still require release SBOM evidence."""
        for optional in ("syn", "proc-macro2", "toml", "toml_edit", "x509-parser"):
            with self.subTest(package=optional):
                doc = sample()
                doc["packages"] = [
                    entry for entry in doc["packages"]
                    if entry["name"] != optional
                ]
                self.write(doc)
                with self.assertRaisesRegex(ValueError, "missing locked"):
                    self.check()
                doc = sample()
                next(entry for entry in doc["packages"] if entry["name"] == optional)[
                    "versionInfo"
                ] = "9.9.9"
                self.write(doc)
                with self.assertRaisesRegex(ValueError, "differs from Cargo.lock"):
                    self.check()
                doc = sample()
                next(entry for entry in doc["packages"] if entry["name"] == optional)[
                    "versionInfo"
                ] = ""
                self.write(doc)
                with self.assertRaisesRegex(ValueError, "unversioned"):
                    self.check()

    def test_explicit_direct_syn_version_with_transitive_syn_is_unambiguous(self):
        """Keep root-selected syn 3 distinct from independently locked syn 2."""
        self.lock.write_text(
            lock_fixture().replace('"syn"', '"syn 1.0.0"', 1)
            + '\n[[package]]\nname = "syn"\nversion = "2.0.0"\n',
            encoding="utf-8",
        )
        self.write(sample())
        self.assertEqual(self.check()["direct_dependency_versions"]["syn"], "1.0.0")
        doc = sample()
        doc["packages"].append({
            "SPDXID": "SPDXRef-syn-transitive",
            "name": "syn", "versionInfo": "2.0.0",
            "downloadLocation": "NOASSERTION",
        })
        self.write(doc)
        self.assertEqual(self.check()["direct_dependency_versions"]["syn"], "1.0.0")

        # A transitive syn 2 entry can never stand in for direct syn 3.
        for entry in doc["packages"]:
            if entry["name"] == "syn" and entry["versionInfo"] == "1.0.0":
                entry["versionInfo"] = "2.0.0"
        self.write(doc)
        with self.assertRaisesRegex(ValueError, "missing locked"):
            self.check()

        # An unrelated version in SPDX is not tolerated even when the
        # required direct version is also present.
        doc = sample()
        doc["packages"].append({
            "SPDXID": "SPDXRef-syn-forged",
            "name": "syn", "versionInfo": "9.9.9",
            "downloadLocation": "NOASSERTION",
        })
        self.write(doc)
        with self.assertRaisesRegex(ValueError, "differs from Cargo.lock"):
            self.check()

    def test_reject_invalid_and_ambiguous_explicit_root_version(self):
        """Root-specified lock versions must identify exactly one package."""
        baseline = lock_fixture()
        for ref in ('"syn 9.9.9"', '"syn not-a-version"', '"syn 1.0.0"',
                    '"syn 1.0.0 (registry+untrusted)"'):
            # With a single syn 1.0.0 package, only the valid exact form
            # is admissible; the other forms cannot resolve.
            modified = baseline.replace('"syn"', ref, 1)
            if ref == '"syn 1.0.0"':
                continue
            self.lock.write_text(modified, encoding="utf-8")
            self.write(sample())
            with self.assertRaises(ValueError):
                self.check()
        self.lock.write_text(
            baseline.replace('"syn"', '"syn 1.0.0"', 1)
            + '\n[[package]]\nname = "syn"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        self.write(sample())
        with self.assertRaisesRegex(ValueError, "ambiguous locked version"):
            self.check()

    def test_extra_unreviewed_root_dependency_cannot_bypass_release_gate(self):
        """Do not silently approve a changed root dependency set."""
        self.lock.write_text(
            lock_fixture().replace('dependencies = [', 'dependencies = ["unreviewed", ', 1),
            encoding="utf-8",
        )
        self.write(sample())
        with self.assertRaisesRegex(ValueError, "direct dependency contract"):
            self.check()

    def test_reject_empty_and_oversized_sbom(self):
        """Fail when the SPDX document is empty or over its memory ceiling."""
        doc = sample()
        doc["packages"] = []
        self.write(doc)
        with self.assertRaisesRegex(ValueError, "empty dependency"):
            self.check()
        self.path.write_bytes(b" " * (16 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "oversized"):
            self.check()


if __name__ == "__main__":
    unittest.main()
