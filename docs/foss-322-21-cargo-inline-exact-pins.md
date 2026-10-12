# FOSS-322.21 — Cargo inline version-only exact dependency declarations

## Problem and dependency

The original FOSS-322 Cargo.toml collector supports an exact-pinned string dependency declaration such as `ring = "=0.17.12"`, but rejects the semantically equivalent common Cargo inline-table form. This increment expands only that safe equivalence while retaining proven Cargo.lock root references, explicit source grants and canonical graph evidence.

Starts from FOSS-322.20 PR #39's verified squash-main. Merge only after CI and review.

## Code-level specification

In `manifest.rs::parse_manifest`, inside `[dependencies]` only, accept exactly:

`name = { version = "=MAJOR.MINOR.PATCH" }`

Whitespace around the braces, `version` key and equals is permitted. Parse as a single inline table with exactly one `version` key, decoded with the existing bounded `quoted` helper. Reuse existing package-name validation and strict three-part canonical numeric pin parser. Map into the **same** manifest `direct` map as an exact string dependency; reuse the existing unchanged lockfile proof and normalization path.

Do not accept aliases (`package`), features, `default-features`, `optional`, workspace/path/git sources, dev/build/target profiles, semver ranges, unsupported prerelease versions, multiple keys, multiline tables, comments, repeated dependency names or malformed source. On unsupported syntax fail closed, not partial-success. No Cargo build, package download, implicit source traversal or cryptographic algorithm-use inference.

## TDD and regression gates

1. Unit: string exact pin versus inline version-only exact pin (including whitespace variants) prove precisely identical root name/version and direct dependency list against the same Cargo.lock fixture.
2. Security: reject absent/extra/duplicate inline keys, optional/feature/alias/git/path/workspace semantics, ranges, invalid numeric versions, truncated/damaged syntax, extra sections, repeated dependency entries and comment injection.
3. Integration: existing authorized CargoManifestCollector/CargoLockfileCollector, canonical dependency edge and tenant/source provenance suite must remain green; no unsupported dependency execution or resolution.
4. Exact-head Linux rustfmt, locked workspace check, strict Clippy, unit/integration/security tests, docs/package, RustSec/deny/SemVer; Windows locked integration; Rust 1.85; independent or automated security review with no unresolved issues.

## Remaining original collector gaps

This does not complete full TOML grammar, Cargo metadata/targets/dev/optional/workspace/version-range support, npm optional/dev/peer/workspace/alias semantics, or bounded incomplete/partial diagnostics. FOSS-322 parent remains In Progress.
