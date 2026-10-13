"""Adversarial unit tests for exact-commit protected release approval."""
import tempfile
import tomllib
import unittest
from pathlib import Path

from verify_publish_gate import select_verified_ci_run, verify_release_manifest

SHA = "a" * 40
REPO = "LATTIX-IO/cryptomap"
VERSION = "0.1.1-alpha.1"


def ci_response():
    """Construct an exact verified main push run, not just a PR check."""
    return {
        "workflow_runs": [
            {
                "id": 321,
                "head_sha": SHA,
                "event": "push",
                "head_branch": "main",
                "name": "Rust CI",
                "path": ".github/workflows/ci.yml",
                "status": "completed",
                "conclusion": "success",
                "repository": {"full_name": REPO},
            }
        ]
    }


class ExactReleaseGateTests(unittest.TestCase):
    """Pin release evidence and local Cargo manifest handling."""

    def setUp(self):
        """Prepare manifest fixtures without any registry or network access."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.workspace = self.dir / "workspace.toml"
        self.crate = self.dir / "crate.toml"
        self.workspace.write_text(
            '[workspace]\nmembers=[]\n[workspace.package]\nversion="0.1.1-alpha.1"\n',
            encoding="utf-8",
        )
        self.crate.write_text(
            '[package]\nname="cryptomap"\nversion.workspace=true\npublish=["crates-io"]\n',
            encoding="utf-8",
        )

    def test_select_exact_successful_main_push(self):
        """Permit only the reviewed main CI run for a selected source commit."""
        self.assertEqual(select_verified_ci_run(ci_response(), SHA, REPO), 321)
        verify_release_manifest(self.crate, self.workspace, VERSION)

    def test_reject_untrusted_ci_runs(self):
        """No stale head, PR, skipped, or spoofed CI can authorize publishing."""
        variants = [
            ("head_sha", "b" * 40),
            ("event", "pull_request"),
            ("head_branch", "other"),
            ("name", "Other workflow"),
            ("path", ".github/workflows/untrusted.yml"),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("conclusion", "skipped"),
            ("id", -1),
            ("id", "321"),
        ]
        for field, value in variants:
            payload = ci_response()
            payload["workflow_runs"][0][field] = value
            with self.assertRaises(ValueError, msg=field):
                select_verified_ci_run(payload, SHA, REPO)
        payload = ci_response()
        payload["workflow_runs"][0]["repository"]["full_name"] = "attacker/cryptomap"
        with self.assertRaises(ValueError):
            select_verified_ci_run(payload, SHA, REPO)

    def test_reject_wrong_repo_and_commit(self):
        """A matching-looking workflow is insufficient for an unapproved source."""
        for sha, repo in [(SHA, "other/repo"), ("bad", REPO), ("b" * 40, REPO)]:
            with self.assertRaises(ValueError):
                select_verified_ci_run(ci_response(), sha, repo)

    def test_reject_missing_or_malformed_workflow_payload(self):
        """Reject absent job evidence and untrusted payload shapes."""
        for payload in [None, {}, {"workflow_runs": {}}, {"workflow_runs": [{}]}]:
            with self.assertRaises(ValueError):
                select_verified_ci_run(payload, SHA, REPO)

    def test_build_and_release_cargo_toolchain_pins_stay_aligned(self):
        """Prevent floating or mismatched Cargo versions from invalidating package bytes."""
        root = Path(__file__).resolve().parents[1]
        toolchain = tomllib.loads(
            (root / "rust-toolchain.toml").read_text(encoding="utf-8")
        )["toolchain"]["channel"]
        self.assertRegex(toolchain, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        for workflow in (
            ".github/workflows/ci.yml",
            ".github/workflows/release-plz.yml",
        ):
            definition = (root / workflow).read_text(encoding="utf-8")
            self.assertEqual(
                definition.count(f"toolchain: '{toolchain}'"),
                2,
                f"candidate/release toolchain drift in {workflow}",
            )
            self.assertNotIn("toolchain: stable", definition)

    def test_reject_accidentally_disabled_or_widened_registry(self):
        """Only the exact, deliberate crates.io allowlist permits this alpha."""
        for setting in ("false", "true", '["other-registry"]', '["crates-io","other"]'):
            self.crate.write_text(
                f'[package]\nname="cryptomap"\nversion.workspace=true\npublish={setting}\n',
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                verify_release_manifest(self.crate, self.workspace, VERSION)

    def test_reject_wrong_candidate_version_or_package(self):
        """Prevent stale version, prerelease drift or misleading package identity."""
        for candidate in ("0.1.0", "0.1.1-alpha.2", "1.0.0", "not-semver"):
            with self.assertRaises(ValueError):
                verify_release_manifest(self.crate, self.workspace, candidate)
        self.crate.write_text(
            '[package]\nname="other"\nversion.workspace=true\npublish=["crates-io"]\n',
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            verify_release_manifest(self.crate, self.workspace, VERSION)


if __name__ == "__main__":
    unittest.main()
