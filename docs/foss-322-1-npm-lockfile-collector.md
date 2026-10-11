# FOSS-322.1 — npm v2/v3 scoped lockfile collector

## Delivered contract

This is the first concrete, read-only dependency collector and a bounded increment of FOSS-322, **not** FOSS-322 completion. The opt-in public 'collectors::dependency::npm::NpmLockfileCollector' implements the existing 'Collector' trait and emits only 'RawFactKind::Dependency' through 'CollectionSink'. It uses a 'CollectionScope' exact 'RawSourceKind::Dependency' file grant and the existing capability-based, no-follow, bounded 'read_bounded' API. No ambient file open, recursive traversal, package install, build/lifecycle script, network request, or package execution occurs.

The caller pins the scope, requested source item, run ID, collector descriptor, and RFC3339 observation time. 'orchestration::collect_normalized' applies the established FOSS-319/FOSS-320 authorization, evidence, coverage and canonical snapshot path; consumers can also use 'scope::collect_scoped' for a raw outcome. File content is SHA-256 fingerprinted without retaining the lockfile blob. Stable event identities bind the exact source item, node_modules path and version. The source path is a bounded nonsecret attribute; two installations of the same package version retain separate event evidence, while the canonical inventory may unify library identity.

## Explicitly supported

- 'package-lock.json' lockfileVersion **2 and 3** with 'packages' records (including nested and scoped 'node_modules' keys).
- Resolved package names and versions only. A package called 'openssl', 'ring', or 'crypto' **does not imply** cryptographic algorithm use or active runtime execution.
- Deterministic parsing, strict duplicate-key rejection, version checks, malformed path/version rejection, raw observation budgets and exact scoped source file access.
- Unsupported local workspace/link entries produce explicit **Partial** source coverage, preserving any valid dependency facts. Malformed or unsupported source formats produce **Failed**, never 'InspectedNoObservation'. Cancelled requests remain NotInspected.

## Deferred to later FOSS-322 increments

- Cargo.toml/Cargo.lock parsing, npm v1 and alternate dependency schemas, manifest-to-lock direct/transitive reconciliation, verified dependency edges, detailed package metadata, incremental checkpointing, precise per-package progress and multi-source aggregate quota recovery.
- Npm's local workspace/link entries are not claimed as inspected, even if some installed packages were identified. A failed aggregate source is not evidence of package absence.
- Package counts and 'asset' identities describe what the source **declares**, not what the application necessarily loads or invokes at runtime.

## Tests and merge gates

Parser unit tests in 'src/collectors/dependency/npm.rs' cover nested/scoped packages, duplicate JSON, unsupported lock versions, traversal, missing versions, workspace partial status, and package-count limits.

End-to-end tests in 'tests/npm_lockfile_contract.rs' verify: real host-granted file read; deterministic two-run replay with unchanged run inputs; integration through the existing canonical normalizer; no fabricated algorithm-use assets; explicit partial coverage; unauthorized read denial; malformed, unsupported, and conflicting JSON without false absence; cancellation and size-budget denial.

Merge only with exact-head green Linux 'cargo fmt', locked check, strict Clippy, workspace tests, rustdoc, package, RustSec, cargo-deny and SemVer, plus Windows and Rust 1.85 CI, and no unresolved review findings. Keep FOSS-322 **In Progress** until Cargo and npm reconciliation, version coverage, diagnostics and full parent acceptance.
