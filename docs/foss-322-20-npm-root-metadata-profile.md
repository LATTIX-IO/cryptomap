# FOSS-322.20 — Strict npm root metadata compatibility

## Scope

Support the most common safe non-dependency root metadata in package.json, without expanding lockfile semantics, collection authority or dependency proof. This increment follows FOSS-322.19 Cargo metadata compatibility.

## Implementation

Extend the strict `npm_manifest.rs::parse_manifest` allowlist with:
- `private`: optional JSON boolean only; no interpretation as an authorization or collection grant.
- `type`: optional, exactly `"commonjs"` or `"module"`, bounded by RawLimits.field_bytes.

Use the existing `StrictJson` duplicate-key rejecting parser. No other package fields become implicitly accepted. `scripts`, `workspaces`, `overrides`, `devDependencies`, `optionalDependencies`, `peerDependencies`, aliases, ranges, malformed JSON, wrong types, duplicate metadata and unsupported module values remain rejected. Manifest root identity/version and exact-pinned production dependency proofs are unchanged; no new raw observation attributes or claim of actual algorithm use is generated.

## TDD and acceptance

1. Unit: baseline and enriched manifests produce identical name/version, package declaration map and complete exact-pin proof for both supported module types and either private boolean, including independently optional metadata keys.
2. Security: malformed/wrong-type metadata, duplicate keys, unexpected package scripts and dependency profiles, bogus type values, duplicate dependency field and excessive field length reject without partial proof.
3. Regression: existing package-lock v2/v3 reconciliation, installed-node path and source-grant tests remain green. No npm execution, network fetch, implicit traversal or invented runtime crypto-use evidence.
4. Merge: after upstream PR #38 squash merges, rebuild branch directly on new main so diff contains only npm metadata code/tests and this SDD. Run exact-head Linux fmt/locked check/strict Clippy/workspace tests/docs/package/RustSec audit/deny/SemVer, Windows locked tests, Rust 1.85 tests, and resolve all actionable reviewers.

## Boundary

This is explicitly **not** full package.json/package-lock semantics. Full Cargo/npm optional/dev/peer/target/workspace/alias/range handling, path-context proof and original FOSS-322 acceptance remain separately tracked. The parent FOSS-322 must remain In Progress.
