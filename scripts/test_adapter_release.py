"""FOSS-486 adversarial archive, SPDX, compatibility and digest-mapping tests."""
import copy
import io
import tomllib
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
dependencies = ["cap-fs-ext", "cap-std", "const-oid", "serde", "serde_json", "sha2", "x509-cert"]

[[package]]
name = "cap-fs-ext"
version = "4.0.3"

[[package]]
name = "cap-std"
version = "4.0.3"

[[package]]
name = "const-oid"
version = "0.9.6"

[[package]]
name = "serde"
version = "1.0.229"

[[package]]
name = "serde_json"
version = "1.0.154"

[[package]]
name = "sha2"
version = "0.10.9"

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
build = false

[lib]
name = "cryptomap_windows_store"
path = "src/lib.rs"

[[example]]
name = "read_user_store"
path = "examples/read_user_store.rs"

[dependencies.cryptomap]
version = "{VERSION}"
features = ["certificate-store-grants"]

[dev-dependencies.x509-cert]
version = "=0.2.5"
default-features = false
features = ["pem", "std"]

[target.'cfg(windows)'.dependencies.windows-sys]
version = "=0.61.2"
features = ["Win32_Foundation", "Win32_Security_Cryptography"]

[lints.rust]
missing_docs = "warn"
unsafe_op_in_unsafe_fn = "deny"

[lints.clippy]
dbg_macro = "deny"
todo = "deny"
unwrap_used = "warn"
expect_used = "warn"
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
                (p["name"], p["version"])
                for p in tomllib.loads(lock_content())["package"]
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
            "Cargo.toml.orig": (
                ROOT / "crates" / ADAPTER / "Cargo.toml"
            ).read_bytes(),
            "Cargo.lock": lock_content().encode(),
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

    def test_reject_hidden_target_build_and_extra_dependency_tables(self):
        approved = test_manifest()
        cases = (
            approved + b'\n[target.\'cfg(target_os = "macos")\'.dependencies]\nmalicious = "1.0.0"\n',
            approved + b'\n[build-dependencies]\nmalicious = "1.0.0"\n',
            approved + b'\n[dependencies.malicious]\nversion = "1.0.0"\n',
            approved.replace(b'features = ["certificate-store-grants"]',
                             b'features = ["certificate-store-grants", "unreviewed"]'),
            approved.replace(b'build = false', b'build = "build.rs"'),
        )
        for change in cases:
            self.make_archive(add={"Cargo.toml": change})
            with self.assertRaises(ValueError):
                self.inspect()
        # Changing both source and normalized archive manifests must not
        # silently redefine the approved dependency boundary.
        self.make_archive(add={"Cargo.toml.orig": b"[package]\nname = 'attacker'\n"})
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

    def test_reject_packaged_lock_forgery_or_omission(self):
        self.make_archive(omit="Cargo.lock")
        with self.assertRaises(ValueError):
            self.inspect()
        self.make_archive(add={"Cargo.lock": lock_content().replace(
            'version = "0.61.2"', 'version = "0.66.6"',
        ).encode()})
        with self.assertRaises(ValueError):
            self.inspect()

    def test_reject_packaged_dependency_edge_tampering(self):
        """Identical package identities alone cannot authenticate the lock graph."""
        original = lock_content()
        root_edges = 'dependencies = ["cryptomap", "windows-sys", "x509-cert"]'
        self.assertIn(root_edges, original)
        cases = (
            original.replace(root_edges, 'dependencies = ["cryptomap", "x509-cert"]'),
            original.replace(root_edges, 'dependencies = ["cryptomap", "cryptomap", "windows-sys", "x509-cert"]'),
            original.replace(root_edges, 'dependencies = ["cryptomap", "windows-sys", "cryptomap"]'),
            original.replace(
                'name = "windows-sys"\nversion = "0.61.2"',
                'name = "windows-sys"\nversion = "0.61.2"\ndependencies = ["cryptomap"]',
            ),
        )
        for modified in cases:
            self.assertNotEqual(modified, original)
            self.make_archive(add={"Cargo.lock": modified.encode()})
            with self.assertRaises(ValueError):
                self.inspect()

        # Equivalent order changes must not invalidate the approved root graph.
        reordered = original.replace(
            root_edges, 'dependencies = ["x509-cert", "cryptomap", "windows-sys"]',
        )
        self.make_archive(add={"Cargo.lock": reordered.encode()})
        self.assertEqual(self.inspect()["crate"], ADAPTER)

    def test_reject_truncated_transitive_graph_and_package_inventory(self):
        """A valid direct root cannot excuse deleting transitive dependencies."""
        source = lock_content()
        original_core = (
            'dependencies = ["cap-fs-ext", "cap-std", "const-oid", '
            '"serde", "serde_json", "sha2", "x509-cert"]'
        )
        self.assertIn(original_core, source)
        mutations = (
            # Drop a real mandatory core edge and its package record.
            source.replace(
                original_core,
                'dependencies = ["cap-std", "const-oid", "serde", "serde_json", "sha2", "x509-cert"]',
            ).replace('[[package]]\nname = "cap-fs-ext"\nversion = "4.0.3"\n\n', ""),
            # Direct root intact, but registry transitive dependencies removed.
            source.replace(
                '[[package]]\nname = "x509-cert"\nversion = "0.2.5"',
                '[[package]]\nname = "x509-cert"\nversion = "0.2.5"\ndependencies = ["serde"]',
            ),
            # Referenced transitive package disappears without fixing its edge.
            source.replace('[[package]]\nname = "sha2"\nversion = "0.10.9"\n\n', ""),
            # Unknown orphaned package not present in the reviewed graph.
            source + '\n[[package]]\nname = "hidden"\nversion = "1.2.3"\n',
        )
        for modified in mutations:
            self.assertNotEqual(modified, source)
            self.make_archive(add={"Cargo.lock": modified.encode()})
            with self.assertRaises(ValueError):
                self.inspect()

    def test_spdx_requires_every_versioned_package_in_verified_adapter_lock(self):
        self.make_archive()
        expected = self.inspect()["locked_package_versions"]
        self.assertEqual(
            validate_adapter_spdx(self.sbom, self.lock, VERSION, expected)["package_count"],
            len(expected),
        )
        valid = sample_spdx()
        for changed in (
            {**valid, "packages": valid["packages"][:-1]},
            {**valid, "packages": valid["packages"] + [valid["packages"][-1]]},
            {**valid, "packages": valid["packages"] + [{
                "SPDXID": "SPDXRef-forged", "name": "unknown",
                "versionInfo": "99.0.0", "downloadLocation": "NOASSERTION",
            }]},
        ):
            self.sbom.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(ValueError):
                validate_adapter_spdx(self.sbom, self.lock, VERSION, expected)

    def test_reject_wrong_revision_and_locked_dependency(self):
        self.make_archive()
        with self.assertRaises(ValueError):
            inspect_adapter(self.adapter, self.lock, self.manifest, "wrong")
        self.lock.write_text(lock_content().replace('version = "0.61.2"', 'version = "0.61.1"'))
        with self.assertRaises(ValueError):
            self.inspect()

    def test_spdx_reject_missing_windows_target_dependency_and_stale_versions(self):
        self.make_archive()
        good = validate_adapter_spdx(
            self.sbom, self.lock, VERSION, self.inspect()["locked_package_versions"]
        )
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
                validate_adapter_spdx(
            self.sbom, self.lock, VERSION, self.inspect()["locked_package_versions"]
        )

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


class ProtectedMainReleaseLifecycleTests(unittest.TestCase):
    """Protect signed release subjects against any destructive checkout action."""

    CHECKOUT_ACTION = "actions/checkout@"
    DOWNLOAD_ACTION = "actions/download-artifact@"
    REQUIRED_ARTIFACTS = frozenset({
        "cryptomap-tested-crate",
        "cryptomap-software-sbom",
        "cryptomap-adapter-tested-crate",
        "cryptomap-adapter-software-sbom",
        "cryptomap-paired-release-evidence",
    })

    @staticmethod
    def parse_actions(section: str) -> list[dict]:
        """Inspect actual YAML step actions, not mutable human-readable labels.

        This reads only the level-six GitHub Actions steps in this workflow,
        preserving unnamed steps. No external YAML dependency or untrusted
        expressions are evaluated. Unknown action syntax is fail-closed.
        """
        import re

        chunks = re.split(r"(?m)^      - ", section)
        if len(chunks) < 2:
            raise AssertionError("missing protected-main steps")
        parsed = []
        for chunk in chunks[1:]:
            name = re.search(r"(?m)^(?:name:|        name:)\s*(.+)\s*$", chunk)
            uses = re.search(r"(?m)^(?:uses:|        uses:)\s*(\S+)", chunk)
            declared_download_name = re.search(
                r"(?m)^          name:\s*([^\s#]+)", chunk
            )
            parsed.append({
                "name": name.group(1) if name else None,
                "uses": uses.group(1) if uses else None,
                "artifact": declared_download_name.group(1)
                if declared_download_name else None,
                "body": chunk,
            })
        return parsed

    @classmethod
    def check_release_actions(cls, section: str) -> None:
        steps = cls.parse_actions(section)
        checkout_indices = [
            i for i, step in enumerate(steps)
            if (step["uses"] or "").startswith(cls.CHECKOUT_ACTION)
        ]
        assert checkout_indices == [0], (
            "exactly one pinned checkout must precede all release artifacts"
        )
        checkout = steps[0]
        assert checkout["uses"] == (
            "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10"
        ), "protected main checkout must be pinned"
        assert "          persist-credentials: false" in checkout["body"], (
            "release checkout must not persist credentials"
        )

        downloads = [
            (index, step["artifact"])
            for index, step in enumerate(steps)
            if (step["uses"] or "").startswith(cls.DOWNLOAD_ACTION)
        ]
        assert len(downloads) == len(cls.REQUIRED_ARTIFACTS), (
            "missing or unexpected signed-input download"
        )
        assert {name for _, name in downloads} == cls.REQUIRED_ARTIFACTS, (
            "downloaded signed input identity differs from release contract"
        )
        assert all(0 < index for index, _ in downloads), (
            "checkout must precede every signed-input download"
        )

        verifying = [
            i for i, step in enumerate(steps)
            if step["name"] == (
                "Verify downloaded exact signed-subject candidates before signing"
            )
        ]
        signing = [
            i for i, step in enumerate(steps)
            if step["name"] == "Sign build provenance for tested candidate"
        ]
        assert len(verifying) == 1 and len(signing) == 1, (
            "missing/duplicate verification or signing step"
        )
        assert max(i for i, _ in downloads) < verifying[0] < signing[0], (
            "signed subjects must be downloaded and verified before signing"
        )
        assert "scripts/verify_adapter_release.py verify" in steps[verifying[0]]["body"], (
            "before-signing verification must perform exact subject check"
        )

    def test_checkout_actions_precede_download_and_cannot_repeat(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        sections = workflow.split("\n  release-attestations:\n", 1)
        self.assertEqual(len(sections), 2)
        original = sections[1]
        self.check_release_actions(original)

        # Rename the checkout label: action-based validation remains effective.
        renamed = original.replace(
            "- name: Read-only main checkout for deterministic mapping verification",
            "- name: Custom checkout label that does not reveal checkout",
            1,
        )
        self.check_release_actions(renamed)

        # A checkout with a different name or no name still erases artifacts.
        injected = (
            "\n      - name: Innocuous cache step\n"
            "        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n"
            "        with:\n"
            "          persist-credentials: false\n"
        )
        unnamed = (
            "\n      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n"
            "        with:\n"
            "          persist-credentials: false\n"
        )
        before_signing = "      - name: Verify downloaded exact signed-subject candidates before signing"
        for bad in (injected, unnamed):
            with self.assertRaises(AssertionError):
                self.check_release_actions(
                    original.replace(before_signing, bad + "\n" + before_signing, 1)
                )

        # Delayed checkout with an innocuous label must also fail.
        checkout_start = original.index(
            "      - name: Read-only main checkout for deterministic mapping verification"
        )
        first_download = original.index(
            "      - name: Download exact CI-tested release candidate"
        )
        checkout_block = original[checkout_start:first_download]
        without_first_checkout = (
            original[:checkout_start] + original[first_download:]
        )
        late_checkout = without_first_checkout.replace(
            before_signing, checkout_block + before_signing, 1
        )
        with self.assertRaises(AssertionError):
            self.check_release_actions(late_checkout)

        # Tamper artifact identity and checkout credentials.
        with self.assertRaises(AssertionError):
            self.check_release_actions(original.replace(
                "name: cryptomap-adapter-software-sbom",
                "name: cryptomap-software-sbom",
                1,
            ))
        with self.assertRaises(AssertionError):
            self.check_release_actions(original.replace(
                "persist-credentials: false", "persist-credentials: true", 1,
            ))


if __name__ == "__main__":
    unittest.main()
