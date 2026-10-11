# FOSS-322.2 — Cargo.lock scoped package presence collector

## Contract and use

The opt-in cryptomap::collectors::dependency::cargo::CargoLockfileCollector implements the existing Collector trait. A trusted host grants each exact Cargo.lock path under CollectionScope::grant_file(RawSourceKind::Dependency, ...) before collection; the caller independently pins run ID, collector descriptor, requested source IDs, tenant IdentityContext, RawLimits, registry and observation time. Use scope::collect_scoped for a raw CollectionOutcome or orchestration::collect_normalized for canonical InventorySnapshot evidence.

No Cargo commands, build scripts, package code, registry lookup, network fetch, implicit search, filesystem recursion, or secret-key retrieval. **Presence of ring, aes-gcm, rustls, or openssl is dependency presence only, not proof of an algorithm's execution.**

## Initial safe profile

- Only explicit Cargo.lock v3/v4, with a version header and repeated [[package]] tables containing quoted name, version, optional source, optional SHA-256 checksum, and optionally a line-oriented dependency-list array.
- No unreviewed TOML escapes, inline arrays, unknown table sections/fields, duplicate package fields, unsupported lockfile versions or syntactically incomplete data are silently accepted. Invalid or unsupported files receive Failed coverage and a typed diagnostic; successful independent sources remain available.
- The parser is intentionally **not a complete TOML parser**. A future increment should use a maintained TOML parser with MSRV/lockfile and security-policy review to support the full Cargo grammar. Until then, unsupported valid TOML also fails closed rather than being incorrectly marked clean.
- Bounded file handles, requested-source authorization, byte limits, raw record and observation budgets, cancellation and exact source provenance are inherited from FOSS-318/319/320. The entire file is parsed before emitting any facts; a malformed lockfile cannot partially establish success coverage.
- RawFactKind::Dependency includes exact ecosystem cargo, package name and resolved version. Source URL is **never serialized**: source identity is SHA-256 hashed as a nonsecret attribute. RawObservation.source_sha256 is the full SHA-256 file digest. Event identity hashes a typed source-item/package/version/source tuple for deterministic replay and different-source separation.
- Dependency strings are syntax-checked but **do not yet generate direct/transitive relationship edges**. Root package-vs-library role and manifest reconciliation are not inferred from lockfile alone.

## Acceptance and verification

Parser unit tests: registry and workspace packages, lockfile v3/v4, unsupported versions and sections, duplicate fields, truncated dependency arrays, malformed input, source URL redaction and resource limits.

End-to-end integration: tests/cargo_lockfile_contract.rs uses generated files and exact grants, exercises the existing sink and collect_normalized pipeline, checks source digests/evidence/canonical AssetKind::Library only, deterministic replay, tenant-bound snapshot verification, mixed-success/failure partial-run preservation, out-of-scope source rejection, read-budget denial, malformed-file coverage, and cancellation.

Required merge gate: exact-final-head Linux cargo fmt, locked workspace check, strict Clippy, locked tests, rustdoc, package, RustSec, dependency policy and semver; Windows integration tests; Rust 1.85 MSRV; unresolved review findings addressed. No merge on pending/failed CI.

## Deferred (FOSS-322 remains in progress)

Full TOML coverage, Cargo.toml manifest declarations, direct/transitive relationship resolution, git/workspace/renamed dependency semantics, npm package.json reconciliation, checkpoint invalidation, support for additional ecosystems, and the full FOSS-322 SDD closeout.
