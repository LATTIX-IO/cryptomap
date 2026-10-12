"""Unit and fail-closed regression tests for release software SBOM validation."""
import json
import tempfile
import unittest
from pathlib import Path

from verify_release_sbom import EXPECTED_DIRECT, validate


def sample():
    """Create a minimal tool-shaped SPDX document with known direct crates."""
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.invalid/spdx/cryptomap-test",
        "creationInfo": {"creators": ["Tool: Syft"]},
        "packages": [
            {"SPDXID": f"SPDXRef-crate-{i}", "name": name, "versionInfo": "1.0.0"}
            for i, name in enumerate(sorted(EXPECTED_DIRECT))
        ],
    }


class SoftwareSbomTests(unittest.TestCase):
    """Test structural failures without depending on remote package feeds."""

    def setUp(self):
        """Prepare an isolated deterministic document path."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "software.spdx.json"

    def write(self, document):
        """Write a synthetic SPDX fixture to disk."""
        self.path.write_text(json.dumps(document), encoding="utf-8")

    def test_valid_software_inventory(self):
        """Accept complete versioned dependency enumeration."""
        self.write(sample())
        result = validate(self.path)
        self.assertEqual(result["spdxVersion"], "SPDX-2.3")
        self.assertEqual(result["package_count"], len(EXPECTED_DIRECT))

    def test_reject_wrong_schema_or_identity(self):
        """Do not silently accept a non-SPDX or anonymous inventory."""
        for field, value in [
            ("spdxVersion", "SPDX-2.2"),
            ("SPDXID", "SPDXRef-other"),
            ("dataLicense", "NOASSERTION"),
            ("documentNamespace", ""),
            ("creationInfo", {}),
        ]:
            doc = sample()
            doc[field] = value
            self.write(doc)
            with self.assertRaises(ValueError):
                validate(self.path)

    def test_reject_missing_or_unversioned_direct_dependency(self):
        """Missing an essential crate or its version invalidates the release."""
        document = sample()
        document["packages"].pop()
        self.write(document)
        with self.assertRaisesRegex(ValueError, "missing locked"):
            validate(self.path)
        document = sample()
        document["packages"][0]["versionInfo"] = ""
        self.write(document)
        with self.assertRaisesRegex(ValueError, "unversioned"):
            validate(self.path)

    def test_reject_duplicate_package_identity(self):
        """Duplicate SPDX identifiers may not silently collapse dependencies."""
        doc = sample()
        doc["packages"][1]["SPDXID"] = doc["packages"][0]["SPDXID"]
        self.write(doc)
        with self.assertRaisesRegex(ValueError, "duplicate package"):
            validate(self.path)

    def test_reject_empty_and_oversized_sbom(self):
        """Reject empty package sets and files above the attestation ceiling."""
        doc = sample()
        doc["packages"] = []
        self.write(doc)
        with self.assertRaisesRegex(ValueError, "empty dependency"):
            validate(self.path)
        self.path.write_bytes(b" " * (16 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "oversized"):
            validate(self.path)


if __name__ == "__main__":
    unittest.main()
