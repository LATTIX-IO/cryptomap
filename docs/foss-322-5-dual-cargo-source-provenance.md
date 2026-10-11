# FOSS-322.5 — Independent Cargo manifest attestation for canonical dependency edges

## Contract

This increment closes the PR #23 evidence gap without introducing new snapshot schema versions, synthetic collection runs, or source privileges. The new passive `CargoManifestCollector` implements the existing versioned `Collector` trait and reads **only** independently approved Cargo.toml file grants through `CollectionScope::open_file` and `read_bounded`. It uses the same narrow fail-closed Cargo.toml exact-pin parser as the earlier reconciler, now restricted to numeric MAJOR.MINOR.PATCH versions (no leading zeros, overflow, prerelease, build metadata, version ranges, or invalid strings). Other Cargo-supported version syntax is deferred rather than misrepresented as confirmed evidence. No Cargo CLI, lifecycle hooks, network fetches, ungranted file traversal, or runtime use inference.

For each accepted manifest, the collector emits separate `RawFactKind::Dependency` observations for the root package and each exact-pinned direct dependency. Events use distinct stable typed hashes, roles `root`/`direct` (raw attribution), and the SHA-256 of the complete authorized manifest. Malformed/unsupported manifests emit no facts and record Failed coverage. Cancellation does not claim clean coverage. Limits account for the extra root observation.

## Dual-source projection

`project_cargo_direct_edges` continues verifying a canonical snapshot against the host's authorized tenant scope and freshly reconciling both exact file grants. It now **requires** existing, persistent, canonical manifest AND lockfile evidence for both root and target, with the current manifest and lockfile SHA-256 digests. Manifest evidence must come from collector `cryptomap:cargo-manifest`, lockfile evidence from `cryptomap:cargo-lockfile`, each `Direct/Confirmed`, with successful typed coverage of the exact source item and both endpoint observations sharing a run **within each source collector**. It does not require the two independent collector runs to have the same ID. Each canonical DependsOn relationship references at least four evidence IDs—root and target manifest plus root and target lockfile—and re-finalizes and verifies its canonical digest.

A lockfile-only snapshot, wrong manifest source, stale manifest bytes, stale lockfile bytes, mixed tenant, missing confirmed observations, malformed source, budget overflow, ambiguous declaration, or ungranted source is rejected; no partially projected snapshot is returned. Replay at the exact relationship budget stays deterministic and idempotent. Both source digests and evidence IDs persist in the resulting canonical snapshot without serializing raw document bytes or registry credentials.

## Verification gates

- Parser, malformed-input, authorization, resource-limit and cancellation collector regression tests in `tests/cargo_manifest_collector_contract.rs`.
- Batch integration using two distinct authorized runs and the canonical `normalize_batch` pathway, with edge evidence assertions and tampered-manifest/lock-only cases in `tests/cargo_direct_projection_contract.rs`.
- Exact PR-head GitHub Actions Linux locked format/check/strict Clippy/unit+integration/security tests/rustdoc/package/dependency audit/SemVer; Windows compatibility; Rust 1.85 MSRV; all actionable security-review findings addressed before merge.

## Explicitly deferred

The supported Cargo.toml profile is still narrow: comprehensive TOML grammar, workspace inheritance, renamed, optional, target, build/dev and ranged dependency handling remain unimplemented. npm package.json reconciliation, transitive edges, cross-manifest linkage, and checkpoint/invalidation support remain FOSS-322 requirements. Do not mark the parent story Done from this increment.
