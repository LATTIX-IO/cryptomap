# Milestone A — 0.1.1-alpha.1 release-candidate gates

## What is and is not authorized

This is a *prepublication* candidate for the evidence-backed Rust inventory SDK, not a full cryptographic-use scanner or CBOM exporter. Merging the candidate code does not authorize a crates.io publish or GitHub release. The manifest remains `publish = false`, and the release-plz action requires manual workflow dispatch plus an explicit repository opt-in.

### Existing immutable registry entry

The authoritative crates.io sparse-index record for `cryptomap` currently contains `0.1.0`, published 2026-10-07T17:27:13Z, checksum `4aeeeefc33256185a4c294c6c18206bf982bd0f16a2b20425f567bbf6f24d25b`, not yanked, and zero listed dependencies. Source: https://github.com/rust-lang/crates.io-index/blob/master/cr/yp/cryptomap . This is not the unpublished full SDK described by this repository. **Never attempt to republish 0.1.0.** Neither this index nor GitHub organization ownership proves who controls the crates.io record.

Selected **candidate version**: `0.1.1-alpha.1`. The version choice is provisional until a fresh registry availability and authenticated publisher-ownership check, conducted immediately before the irreversible publish.

## Completed-in-code acceptance criteria

1. Root workspace package version, lockfile root and `.crate` manifest must agree exactly on `0.1.1-alpha.1`; no dependency or collector contract version is silently reinterpreted.
2. The release inspector derives one expected version from the **checked-out workspace Cargo.toml and reviewed Cargo.lock root**, and rejects any archive that does not match that version—even if its filename, tar root and embedded manifest agree with each other. Security regressions include stale self-consistent 0.1.0 archives, wrong archive labels, lockfile drift and positive prerelease acceptance.
3. Crate stays `publish = false` through all feature, security, identity and SPDX/provenance PRs. Every CI run must pass Linux strict format/check/Clippy/tests/docs/package/offline external consumers/RustSec/deny/SemVer, Windows and Rust 1.85.
4. Source-scoped Cargo and npm examples, frozen asset:v2 identity cases, packaging/integrity tests, reviewed software SPDX SBOM and successful main-only Sigstore attestations are required; no false CBOM, TLS, source-use or recursive scanner claims.
5. Security reviews and all actionable issues must close on exact final-head source. Evidence links and the release decision must be captured by a maintainer.

## External human approval — hard stop

1. Authenticate to crates.io and verify that the intended publisher is an owner of the existing `cryptomap` crate; if not, **stop** and negotiate ownership/rename instead of changing version to bypass ownership.
2. Refresh the official crates.io index; verify `0.1.1-alpha.1` is unused and `0.1.0` is not the release candidate. Confirm registry availability without relying solely on stale mirrors.
3. Verify repository-admin access, release-plz publishing credentials/trusted publishing configuration, least-privilege token scope, and required environment/branch protection reviewers. Do not put tokens into source or PR logs.
4. A *separate*, explicitly approved publication PR may change `publish = false` to the exact `publish = ["crates-io"]` registry allowlist and update final release metadata. Review that PR independently, resolving any registry/API errors and CI release-evidence gate requirements; the protected workflow itself requires `cargo publish --dry-run --package cryptomap --locked`.
5. Configure the `cryptomap-publish` GitHub Environment with required reviewers and main-branch restrictions **before** dispatch. Publish only through the protected workflow after supplying the explicit `approved_sha` and `approved_version` inputs, and after its exact-main-SHA signed CI/artifact attestations and byte-for-byte package verification succeed. Do not use ordinary merge/push to publish. See [protected publishing protocol](milestone-a-protected-publishing.md).
6. After publish, validate a fresh unrelated `cargo add cryptomap@0.1.1-alpha.1` registry consumer, docs.rs, owner entries, package checksum, signed provenance, software SBOM and public GitHub release. Update release notes only after these checks actually pass.

## Deferred beyond Milestone A

No claim of general source-code crypto-use detection, public certificate/TLS or runtime telemetry collectors, automatic repo scan/CLI, complete Cargo/npm dependency profile resolution, CycloneDX CBOM, compliance decision, cryptopolicy/cryptoshift migration, or stable 1.0 API compatibility. Those remain Milestones B–D.

A release candidate is mergeable when code/CI/reviews are green, but **not publishable** until the external authenticated owner and token checks pass and separate publication approval is recorded.
