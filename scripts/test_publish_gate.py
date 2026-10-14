"""Adversarial unit tests for exact-commit protected release approval."""
import re
import shlex
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

    def test_both_workflows_require_exact_source_bound_dual_attestations(self):
        """Never accept a valid signature for the wrong signer, ref or commit."""
        root = Path(__file__).resolve().parents[1]
        for workflow, anchor in (
            (".github/workflows/ci.yml", "      - name: Verify published provenance and SBOM signatures"),
            (".github/workflows/release-plz.yml",
             "      - name: Verify exact CI-tested crate and both main attestations"),
        ):
            content = (root / workflow).read_text(encoding="utf-8")
            section = content.split(anchor, 1)[1]
            if workflow.endswith("release-plz.yml"):
                section = section.split("      - name: Registry dry-run of reviewed version", 1)[0]
            with self.subTest(workflow=workflow):
                self._require_exact_attestation_contract(section)

                # Adversarial mutation: all identity dimensions are required,
                # including BOTH distinct verified predicates.
                for vital in (
                    '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/ci.yml"',
                    '--source-ref refs/heads/main',
                    '--source-digest "$GITHUB_SHA"',
                    "--predicate-type https://spdx.dev/Document/v2.3",
                    'gh attestation verify "${candidates[0]}" "${attestation_scope[@]}"',
                ):
                    self.assertIn(vital, section)
                    with self.assertRaises(AssertionError, msg=f"{workflow}: {vital}"):
                        self._require_exact_attestation_contract(section.replace(vital, "REMOVED", 1))
                # Regressions that keep both command substrings but silently
                # switch the first/default SLSA verification to SPDX.
                first = 'gh attestation verify "${candidates[0]}" "${attestation_scope[@]}"'
                poisoned = section.replace(
                    first + "\n", first + " --predicate-type https://spdx.dev/Document/v2.3\n", 1
                )
                with self.assertRaises(AssertionError):
                    self._require_exact_attestation_contract(poisoned)
                poisoned_scope = section.replace(
                    '--source-digest "$GITHUB_SHA"',
                    '--source-digest "$GITHUB_SHA" --predicate-type https://spdx.dev/Document/v2.3',
                    1,
                )
                with self.assertRaises(AssertionError):
                    self._require_exact_attestation_contract(poisoned_scope)
                # A later predicate flag overrides the earlier SPDX flag.
                # The contract must validate whole continued shell commands.
                poisoned_second = section.replace(
                    '--predicate-type https://spdx.dev/Document/v2.3',
                    '--predicate-type https://spdx.dev/Document/v2.3 '
                    '--predicate-type https://slsa.dev/provenance/v1',
                    1,
                )
                with self.assertRaises(AssertionError):
                    self._require_exact_attestation_contract(poisoned_second)
                # Repeated selectors must not supersede approved earlier values.
                for suffix in [
                    '            --source-digest "$OTHER_SHA"\n',
                    '            --source-ref refs/heads/untrusted\n',
                    '            --predicate-type https://spdx.dev/Document/v2.3\n',
                ]:
                    mutated = section.replace(
                        '            --source-digest "$GITHUB_SHA"\n',
                        '            --source-digest "$GITHUB_SHA"\n' + suffix,
                        1,
                    )
                    with self.assertRaises(AssertionError):
                        self._require_exact_attestation_contract(mutated)
                mutated = section.replace(
                    '\n          )\n',
                    '\n          )\n          attestation_scope+=(--source-digest "$OTHER_SHA")\n',
                    1,
                )
                with self.assertRaises(AssertionError):
                    self._require_exact_attestation_contract(mutated)
                # Indirect writes cannot be detected by checking only lines
                # that *begin* with attestation_scope.
                for injection in [
                    "printf -v 'attestation_scope[7]' %s ffffffffffffffffffffffffffffffffffffffff",
                    'eval \'attestation_scope[7]="$OTHER_SHA"\'',
                    'declare -a attestation_scope=()',
                ]:
                    mutated = section.replace(
                        '          )\n',
                        '          )\n          ' + injection + '\n',
                        1,
                    )
                    with self.assertRaises(AssertionError, msg=injection):
                        self._require_exact_attestation_contract(mutated)


    def _require_exact_attestation_contract(self, step):
        """Ensure both predicates use the same exact-host and source identity."""
        required = (
            'attestation_scope=(',
            '--repo "$GITHUB_REPOSITORY"',
            '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/ci.yml"',
            '--source-ref refs/heads/main',
            '--source-digest "$GITHUB_SHA"',
            'gh attestation verify "${candidates[0]}" "${attestation_scope[@]}"',
            'gh attestation verify "${candidates[0]}" "${attestation_scope[@]}" \\\n'
            '            --predicate-type https://spdx.dev/Document/v2.3',
        )
        for phrase in required:
            self.assertIn(phrase, step)
        # Freeze every executable line from declaration through BOTH checks:
        # a valid-looking array can otherwise be overwritten by 'printf -v',
        # eval or an indirect Bash assignment before the verifier executes.
        # This gate intentionally requires deliberate code review for changes
        # in this security-sensitive invocation block.
        marker = "          attestation_scope=(\n"
        second = "            --predicate-type https://spdx.dev/Document/v2.3"
        self.assertEqual(step.count(marker), 1)
        self.assertEqual(step.count(second), 1)
        start = step.index(marker)
        stop = step.index(second, start) + len(second)
        actual_block = step[start:stop]
        common = [
            '          attestation_scope=(',
            '            --repo "$GITHUB_REPOSITORY"',
            '            --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/ci.yml"',
            '            --source-ref refs/heads/main',
            '            --source-digest "$GITHUB_SHA"',
            '          )',
            '          gh attestation verify "DOLLAR{candidates[0]}" "DOLLAR{attestation_scope[@]}"',
        ]
        ci_comment = [
            '          # GitHub CLI defaults to SLSA; verify SPDX separately or the SBOM',
            '          # signature may be missing while the provenance check still passes.',
        ]
        spdx = [
            '          gh attestation verify "DOLLAR{candidates[0]}" "DOLLAR{attestation_scope[@]}" \\',
            '            --predicate-type https://spdx.dev/Document/v2.3',
        ]
        expected = [
            "\n".join(common + spdx).replace("DOLLAR", "$"),
            "\n".join(common + ci_comment + spdx).replace("DOLLAR", "$"),
        ]
        self.assertIn(actual_block, expected)

        # Compare the FULL shell invocations, including continuation lines.
        # Substring checks miss later overriding --predicate-type flags.
        joined = re.sub(r"\\\r?\n[ \t]*", " ", step)
        commands = [
            shlex.split(line.strip())
            for line in joined.splitlines()
            if line.strip().startswith("gh attestation verify ")
        ]
        command = ["gh", "attestation", "verify",
                   "${candidates[0]}", "${attestation_scope[@]}"]
        self.assertEqual(commands, [
            command,
            command + ["--predicate-type", "https://spdx.dev/Document/v2.3"],
        ])
        # Parse the effective shell array, not the opaque reference: later
        # duplicate flags could override the approved identities.
        scope = re.search(
            r"(?m)^ {10}attestation_scope=\(\n((?: {12}[^\n]*\n)+) {10}\)$",
            step,
        )
        self.assertIsNotNone(scope)
        self.assertEqual(
            shlex.split(scope.group(1)),
            ["--repo", "$GITHUB_REPOSITORY",
             "--signer-workflow", "$GITHUB_REPOSITORY/.github/workflows/ci.yml",
             "--source-ref", "refs/heads/main",
             "--source-digest", "$GITHUB_SHA"],
        )
        # Reject subsequent array reassignments/appends before verification.
        mutations = [
            line.strip() for line in step.splitlines()
            if line.strip().startswith(("attestation_scope=", "attestation_scope+=",
                                        "attestation_scope["))
        ]
        self.assertEqual(mutations, ["attestation_scope=("])

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
