"""Documentation regression checks for the read-only Windows release walk-through.

This checks references and safeguards, not Rust collector runtime behavior.
The walkthrough intentionally requires individual human-observed commands.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs/milestone-a-windows-manual-validation.md"


class ManualAcceptanceGuideTests(unittest.TestCase):
    def test_guide_and_links_exist(self):
        body = GUIDE.read_text(encoding="utf-8")
        self.assertGreater(len(body), 4000)
        self.assertIn("docs/milestone-a-windows-manual-validation.md",
                      (ROOT / "README.md").read_text(encoding="utf-8"))
        for rel in ["docs/milestone-a-release-readiness.md",
                    "docs/milestone-a-sdk-compatibility.md"]:
            self.assertIn("milestone-a-windows-manual-validation.md",
                          (ROOT / rel).read_text(encoding="utf-8"))

    def test_commands_reference_real_examples_and_test_targets(self):
        body = GUIDE.read_text(encoding="utf-8")
        for example in ["cargo_scoped_inventory", "npm_scoped_inventory"]:
            self.assertTrue((ROOT / f"crates/cryptomap/examples/{example}.rs").is_file())
            self.assertIn(f"--example {example}", body)
        for test in ["milestone_a_identity_golden", "milestone_a_snapshot_diff_golden",
                     "milestone_a_collector_robustness",
                     "milestone_a_inventory_scale_smoke", "foss_369_isolation",
                     "foss_370_rust_source"]:
            self.assertTrue((ROOT / f"crates/cryptomap/tests/{test}.rs").is_file())
            self.assertIn("--test " + test, body)
        self.assertTrue((ROOT / "scripts/release_evidence.py").is_file())
        self.assertIn("test_release_evidence.py", body)
        self.assertIn("cryptomap-tested-crate", body)

    def test_disallowed_release_operations_never_appear_as_shell_commands(self):
        body = GUIDE.read_text(encoding="utf-8")
        blocks = re.findall(r"~~~powershell\n(.*?)\n~~~", body, re.DOTALL)
        self.assertGreaterEqual(len(blocks), 6)
        for block in blocks:
            for line in block.splitlines():
                stripped = line.strip().lower()
                self.assertFalse(re.match(r"(?:&\s*)?(?:cargo\s+publish|gh\s+workflow\s+run|"
                                          r"gh\s+release\s+create|git\s+tag|gh\s+secret\s+set|"
                                          r"gh\s+variable\s+set)\b", stripped),
                                 msg=line)

    def test_exact_main_ci_workflow_selected(self):
        body = GUIDE.read_text(encoding="utf-8")
        for term in ["--json headSha,status,conclusion,event,headBranch,workflowName,workflowDatabaseId",
                     "gh api repos/LATTIX-IO/cryptomap/actions/workflows/ci.yml",
                     "$ci.headBranch -ne 'main'", "$ci.workflowName -ne 'Rust CI'",
                     "$ci.workflowDatabaseId -ne $workflow.id",
                     "$workflow.path -ne '.github/workflows/ci.yml'"]:
            self.assertIn(term, body)

    def test_both_attestation_predicates_pin_main_commit_and_signer(self):
        body = GUIDE.read_text(encoding="utf-8")
        self.assertIn("'--source-digest', $approvedMainSha", body)
        self.assertIn("'--source-ref', 'refs/heads/main'", body)
        self.assertIn("'--signer-workflow', 'LATTIX-IO/cryptomap/.github/workflows/ci.yml'", body)
        self.assertIn("gh attestation verify $ciCrates[0].FullName @attestationScope\n", body)
        self.assertIn("gh attestation verify $ciCrates[0].FullName @attestationScope --predicate-type https://spdx.dev/Document/v2.3", body)
        self.assertEqual(body.count("gh attestation verify $ciCrates[0].FullName @attestationScope"), 2)

    def test_offline_preconditions_pin_both_toolchains(self):
        body = GUIDE.read_text(encoding="utf-8")
        self.assertIn("both Rust 1.99.0", body)
        self.assertIn("Rust 1.85.0", body)
        self.assertIn("rust-toolchain.toml", body)
        self.assertIn("network download", body)

    def test_scope_and_supply_chain_invariants_are_not_erased(self):
        body = GUIDE.read_text(encoding="utf-8")
        for term in ["same verified snapshot", "Tenant separation",
                     "Expected rejection", "publish = false",
                     "https://spdx.dev/Document/v2.3", "post-publish",
                     "authenticated", "not a cryptographic signature",
                     "Read the outputs"]:
            self.assertIn(term.lower(), body.lower())
        self.assertNotIn("setx CARGO_REGISTRY_TOKEN", body)


if __name__ == "__main__":
    unittest.main()
