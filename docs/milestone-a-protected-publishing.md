# Milestone A — protected exact-commit crates.io release gate

## Scope

This is a **publication authorization gate**, not an authorization to publish the current crate. The SDK candidate remains `publish = false`. No release token, registry owner record or environment approval is accessible to this repository-only implementation.

For the first authorized alpha, an administrator must verify authenticated crates.io ownership of the existing `cryptomap` entry and that `0.1.1-alpha.1` is still available. If the intended publisher is not an owner, **stop**. Do not publish under a higher version or alternate account to evade registry ownership.

## Hard-stop workflow conditions

`.github/workflows/release-plz.yml` refuses to execute a release except when **all** of the following are true:

1. Trigger is explicit `workflow_dispatch`, on `LATTIX-IO/cryptomap` `main`, never a push or pull request.
2. Repository variable `CRYPTOMAP_RELEASE_ENABLED` equals `true`.
3. Required dispatch input `approved_sha` exactly equals the checked-out, reviewed 40-hex main commit; `approved_version` exactly matches the proposed alpha version.
4. The release job enters `cryptomap-publish` GitHub Environment. A repository administrator MUST configure required human reviewers and deployment/branch restrictions for this environment **before** approving a release. Naming the environment in YAML does not itself configure reviewer protections.
5. The checked-out crate's `publish` is *explicitly* `["crates-io"]` and package version derives from the workspace's exact approved prerelease version. Enabling it requires a **separate, reviewed and authorized publication PR**.
6. The official `Rust CI` workflow must have completed successfully on a main **push** for the *exact same* commit, with the signed-provenance job included. A successful PR check, skipped attestation, failed/in-progress CI, tag, another repo or stale commit does not qualify.
7. The release workflow downloads exactly that CI run's tested `.crate` artifact and verifies both GitHub/Sigstore provenance and SPDX attestation predicates. The candidate main CI and manual publishing workflow **both use Rust/Cargo 1.99.0**, recorded in `rust-toolchain.toml` and the two GitHub Actions workflows. This prevents floating `stable` toolchain drift between packaging steps. A fresh package of the reviewed main tree must match the exact artifact bytes. Any toolchain upgrade must change all three settings under code review and rerun the complete quality and provenance matrix; the independent Rust 1.85 MSRV check is unchanged.
8. `cargo publish --dry-run --package cryptomap --locked` must succeed before release-plz obtains publishing permission. Only afterward may the manual release action run.

Release runs are serialized by a concurrency group and never canceled to replace an in-progress publication. Do not introduce automatic retries of irreversible registry publishing.

## Test and review evidence

```shell
python3 -m unittest discover -s scripts -p 'test_publish_gate.py' -v
```

The tests explicitly reject alternate repo/commit/branch/event, PR/in-progress/failed CI, wrong workflow identity, malformed API payloads, disabled or widened registry authorization, stale/misnamed versions and incorrect crate name. A passing synthetic test does **not** verify that the required GitHub Environment is configured, secrets exist, or crates.io grants ownership. Those remain human checks.

## Required human verification and post-publish closure

Record in release approval: authenticated crates.io owner identity and membership, current version availability, approved main SHA and crate version, exact GitHub CI job URL and artifact digest, software SBOM, both signed attestation verification outputs, security reviewer approval, environment required reviewers, registry credential scope, and post-publish acceptance owner.

After first publication, use a new unrelated project to install the **registry-distributed** crate, run the Cargo/npm quickstart and collector smoke, validate the package SHA-256 against the approved release, and check docs.rs and GitHub release artifacts. Do not mark Milestone A's **published release** Done before this has actually happened.

A mergeable SDK alpha source release can be ready before these external operations. This workflow does not change the distinction.
