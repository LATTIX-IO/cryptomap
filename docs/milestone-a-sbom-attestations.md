# Milestone A — software SBOM and signed build attestations

## Scope and evidence trust

This gate reports the **software dependencies used to build Cryptomap itself**; it does not export Cryptomap's cryptographic inventory as a CBOM. The SPDX 2.3 document is produced by Syft from the crate's packaged Cargo manifest plus the reviewed workspace Cargo.lock. It may include extra locked workspace dependencies not reachable from the shipped library; do not treat the report as an exact runtime execution trace or a vulnerability assessment.

The previous inspection gate independently records the exact packaged .crate SHA-256 and source commit. This increment requires the SPDX document to contain the reviewed direct SDK dependencies (serde, serde_json, sha2, cap-std, cap-fs-ext, plus feature-gated syn and proc-macro2) with exact locked versions. Failing to detect those packages is a build failure, not a clean/empty SBOM.

## CI execution model

- Ordinary PRs: generate the source-locked SPDX inventory, validate SPDX structure, reject empty/missing/versionless direct dependencies, run adversarial verifier tests and upload the candidate crate and SBOM. GitHub Actions stays at contents: read, **without** an OIDC signing token on PR jobs.
- Trusted main push only: after *all* Linux, Rust 1.85 and Windows quality/security jobs pass, a separate job downloads the exact CI-tested crate artifact and the validated SPDX SBOM from **that same workflow run**. It signs both SLSA build-provenance and an SPDX SBOM attestation via the GitHub-hosted Sigstore integration, then independently verifies the exact CI-built artifact with **both** predicates. Verification is pinned to the official CI signer workflow, `refs/heads/main`, and the exact main source commit digest; a signature issued for identical bytes by a different revision, ref or workflow does not satisfy this acceptance policy. The separately protected manual publication workflow enforces these same attestation identity checks before registry dry-run. This is not executable on fork or untrusted PR code.
- All third-party GitHub Actions are pinned to specific commits. Private repository attestation availability depends on plan; LATTIX-IO/cryptomap must remain public or use supported enterprise authorization.
- The crate itself remains publish = false; signing a candidate does **not** publish a release, reserve a crates.io name, or authorize registry access.

## Quality and security tests

    python3 -m unittest discover -s scripts -p 'test_release_sbom.py' -v
    python3 scripts/verify_release_sbom.py target/release-evidence/cryptomap.spdx.json

The generator uses the pinned anchore/sbom-action/Syft release (SPDX JSON). verify_release_sbom.py is a fail-closed structural/content guard, **not** a complete SPDX schema validator, signature verifier or license policy engine.

Critical acceptance:

1. Source archive remains create-only/safe and is tested as a *crate* in a separate offline consumer.
2. Software SBOM must be nonempty, well-structured SPDX 2.3, bounded (16 MiB max), with unique SPDX package identifiers, and contain all seven reviewed direct SDK dependencies, including optional parser crates with versions.
3. Regression tests reject invalid SPDX version, document identity, missing metadata, missing/empty package set, duplicate package identity, missing/versionless direct dependencies and over-budget files.
4. No OIDC signing permission exists on PR checkout/execution paths. Main attestations require successful exact-head Linux/Windows/MSRV and attest only the artifact that those jobs built and tested.
5. Successful main-run attestation ID and verification output must be recorded in the release checklist. A successful PR test alone does **not** establish that signing worked.

## Remaining release approval

Before publishing the distinct `0.1.1-alpha.1` candidate (the registry already contains `cryptomap 0.1.0`): validate the exact registry name and organization ownership, choose/freeze the version and changelog, explicitly approve a separate change from publish = false, validate the actual registry dry-run/credentials, perform a protected manual release dispatch, then independently install the published registry crate and verify docs.rs plus the signed artifact records. No current CI can test that last registry-distributed installation before a first publication.
