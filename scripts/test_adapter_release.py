"""FOSS-486 adversarial archive, SPDX, compatibility and digest-mapping tests."""
import copy
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from verify_adapter_release import (
    ADAPTER, CORE, inspect_adapter, validate_adapter_spdx, verify_mapping, digest,
)

VERSION = "0.1.1-alpha.1"
REVISION = "a" * 40
ROOT = Path(__file__).resolve().parents[1]


def lock_content() -> str:
    return """version = 4

[[package]]
name = "cryptomap"
version = "0.1.1-alpha.1"

[[package]]
name = "cryptomap-windows-store"
version = "0.1.1-alpha.1"
dependencies = ["cryptomap", "windows-sys", "x509-cert"]

[[package]]
name = "windows-sys"
version = "0.61.2"

[[package]]
name = "x509-cert"
version = "0.2.5"
"""


def test_manifest(publish=False) -> bytes:
    return f"""[package]
name = "{ADAPTER}"
version = "{VERSION}"
publish = {str(publish).lower()}
edition = "2024"
rust-version = "1.85"
license = "MIT OR Apache-2.0"
[dependencies]
cryptomap = {{ version = "{VERSION}" }}
[target.'cfg(windows)'.dependencies]
windows-sys = {{ version = "=0.61.2" }}
""".encode()


def sample_spdx() -> dict:
    return {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
        "dataLicense": "CC0-1.0", "name": "adapter-sbom",
        "documentNamespace": "https://example.invalid/spdx/adapter",
        "creationInfo": {"created": "2026-10-18T12:00:00Z", "creators": ["Tool: Syft"]},
        "packages": [
            {"SPDXID": f"SPDXRef-{i}", "name": name, "versionInfo": vers,
             "downloadLocation": "NOASSERTION"}
            for i, (name, vers) in enumerate([
                ("cryptomap", VERSION), ("windows-sys", "0.61.2"),
                ("x509-cert", "0.2.5"),
            ])
        ],
    }


class AdapterReleaseSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.manifest = self.dir / "Cargo.toml"
        self.manifest.write_text(
            '[workspace.package]\nversion = "0.1.1-alpha.1"\n', encoding="utf-8"
        )
        self.lock = self.dir / "Cargo.lock"
        self.lock.write_text(lock_content(), encoding="utf-8")
        self.adapter = self.dir / f"{ADAPTER}-{VERSION}.crate"
        self.sbom = self.dir / "adapter.spdx.json"
        self.sbom.write_text(json.dumps(sample_spdx()), encoding="utf-8")

    def make_archive(self, *, publish=False, omit=None, add=None):
        files = {
            "Cargo.toml": test_manifest(publish),
            "README.md": b"Read only",
            "LICENSE-MIT": b"MIT",
            "LICENSE-APACHE": b"Apache 2.0",
            "src/lib.rs": b"// safe fixture",
            "examples/read_user_store.rs": b"// manual fixture only",
        }
        for name in ("rsa.pem", "ec.pem"):
            files[f"examples/fixtures/certificate/{name}"] = (
                ROOT / "crates" / "cryptomap" / "examples" / "fixtures"
                / "certificate" / name
            ).read_bytes()
        if omit:
            files.pop(omit)
        if add:
            files.update(add)
        prefix = f"{ADAPTER}-{VERSION}/"
        with tarfile.open(self.adapter, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
            for path, data in files.items():
                info = tarfile.TarInfo(prefix + path)
                info.size = len(data)
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(data))

    def inspect(self):
        return inspect_adapter(self.adapter, self.lock, self.manifest, REVISION)

    def test_valid_archive_is_unpublishable_and_exactly_pinned(self):
        self.make_archive()
        result = self.inspect()
        self.assertEqual(result["crate"], ADAPTER)
        self.assertEqual(result["sha256"], digest(self.adapter))
        self.assertFalse(result["publish_enabled"])
        self.assertFalse(result["registry_resolvable"])
        self.assertEqual(result["dependencies"]["windows-sys"], "0.61.2")

    def test_reject_publish_enabled_and_missing_license(self):
        self.make_archive(publish=True)
        with self.assertRaises(ValueError):
            self.inspect()
        self.make_archive(omit="LICENSE-APACHE")
        with self.assertRaises(ValueError):
            self.inspect()

    def test_reject_unreviewed_key_or_fixture_tampering(self):
        self.make_archive(add={"src/secret.key": b"private"})
        with self.assertRaises(ValueError):
            self.inspect()
        self.make_archive(add={"examples/fixtures/certificate/rsa.pem": b"malicious"})
        with self.assertRaises(ValueError):
            self.inspect()

    def test_reject_unapproved_files_and_directory_shadow(self):
        self.make_archive(add={"src/hidden.bin": b"unreviewed bytes"})
        with self.assertRaises(ValueError):
            self.inspect()
        # A malicious TAR entry with a path under a declared regular file
        # must never be accepted as a nested member.
        self.make_archive(add={"src/lib.rs/surprise.txt": b"content"})
        with self.assertRaises(ValueError):
            self.inspect()

    def test_reject_wrong_revision_and_locked_dependency(self):
        self.make_archive()
        with self.assertRaises(ValueError):
            inspect_adapter(self.adapter, self.lock, self.manifest, "wrong")
        self.lock.write_text(lock_content().replace('version = "0.61.2"', 'version = "0.61.1"'))
        with self.assertRaises(ValueError):
            self.inspect()

    def test_spdx_reject_missing_windows_target_dependency_and_stale_versions(self):
        good = validate_adapter_spdx(self.sbom, self.lock, VERSION)
        self.assertEqual(good["direct_dependencies"]["windows-sys"], "0.61.2")
        source = sample_spdx()
        for altered in [
            {**source, "packages": source["packages"][:1] + source["packages"][2:]},
            {**source, "packages": [{**p, "versionInfo": "0.60.0"}
                                     if p["name"] == "windows-sys" else p
                                     for p in source["packages"]]},
            {**source, "spdxVersion": "SPDX-2.2"},
        ]:
            self.sbom.write_text(json.dumps(altered))
            with self.assertRaises(ValueError):
                validate_adapter_spdx(self.sbom, self.lock, VERSION)

    def test_mapping_ref_digest_swapped_archive_and_sbom_negative_cases(self):
        core = self.dir / f"{CORE}-{VERSION}.crate"
        core.write_bytes(b"core")
        self.adapter.write_bytes(b"adapter")
        core_sbom = self.dir / "core.spdx.json"
        core_sbom.write_bytes(b"core SBOM")
        mapping = {
            "schema": "cryptomap:paired-release-v1",
            "commit": REVISION, "version": VERSION, "publish_enabled": False,
            "source_distribution_only": True,
            "core": {"archive": core.name, "sha256": digest(core),
                     "sbom": core_sbom.name, "sbom_sha256": digest(core_sbom),
                     "direct_dependencies": {}},
            "adapter": {"archive": self.adapter.name, "sha256": digest(self.adapter),
                        "sbom": self.sbom.name, "sbom_sha256": digest(self.sbom),
                        "direct_dependencies": {"cryptomap": VERSION, "windows-sys": "0.61.2"}},
            "dependency_edge": {
                "from": f"{ADAPTER}@{VERSION}", "to": f"{CORE}@{VERSION}",
                "mode": "offline-local-source-pair",
            },
        }
        verify_mapping(mapping, core, self.adapter, core_sbom, self.sbom, REVISION)
        for altered in [
            {**mapping, "commit": "b"*40},
            {**mapping, "dependency_edge": {"from": "malicious", "to": "core"}},
            {**mapping, "adapter": {**mapping["adapter"], "sha256": "0"*64}},
            {**mapping, "adapter": {**mapping["core"]}},
            {**mapping, "publish_enabled": True},
        ]:
            with self.assertRaises(ValueError):
                verify_mapping(altered, core, self.adapter, core_sbom, self.sbom, REVISION)
        self.sbom.write_bytes(b"modified SBOM")
        with self.assertRaises(ValueError):
            verify_mapping(mapping, core, self.adapter, core_sbom, self.sbom, REVISION)


if __name__ == "__main__":
    unittest.main()
