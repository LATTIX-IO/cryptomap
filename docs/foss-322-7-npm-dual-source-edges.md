# FOSS-322.7 — Dual-source canonical npm dependency evidence

## Increment and public interface

This increment extends the existing, conservative FOSS-322.6 npm direct-resolution proof with independently persisted canonical provenance and opt-in graph projection.

- `NpmManifestCollector` is a passive, separately authorized package.json collector. It uses the existing strict JSON duplicate-key rejecting parser, validates only the supported exact numeric production dependency profile, and emits separate root and direct-dependency package-presence observations with file SHA-256, stable typed event IDs and `npm:manifest-role` attributes.
- `NpmLockfileCollector` now includes a root package-presence observation when the package-lock v2/v3 root table has **both valid name and version**. This consumes an observation budget slot. Root tables without either field retain previous behavior. Partially declared or invalid roots force explicit incomplete coverage rather than pretending a confirmed root.
- `project_npm_direct_edges(snapshot,scope,manifest_item,lock_item,raw_limits,inventory_limits)` requires **two separately granted exact file paths**, freshly reconciles their bytes and validates a canonical tenant-bound snapshot. The root and each dependency must exist as matching npm Library assets and each must have direct, confirmed, successful, same-run evidence under **both** the npm lockfile and npm manifest collector, with the appropriate current full-file SHA-256, exact source item and typed coverage. It creates deterministic canonical `DependsOn` relationships referencing at least four previously persisted evidence IDs, then re-finalizes and re-verifies the returned snapshot.

No implicit file traversal, npm execution, package scripts, remote registry fetch, algorithm use inference, synthetic runs, unverified package evidence, or failure-to-absence reinterpretation is allowed. Missing or stale evidence, malformed sources, absent grants, tenant mismatch, source-item mismatch, inconsistent lock/manifest dependency classifications and resource exhaustion fail closed without partial graph output. Existing edges are idempotently replayed without using another relationship slot.

## Acceptance evidence and threat cases

Parser and collector units cover root identity, observation quotas, unsupported partial root semantics and source limits. `npm_manifest_collector_contract.rs` covers authorized deterministic root/dependency emission, malformed versions, invalid names, duplicate JSON keys, unsupported optional/workspace/script semantics, denied grants, file and observation budgets and cancellation. `npm_direct_projection_contract.rs` covers two independent collection runs normalized via `normalize_batch`, cryptographically digested and persisted root/target attestations, canonical replay, exact budget, lock-only denial, cross-tenant denial, missing grants, stale manifest/lockfile bytes, source-item mismatch and invalid pins. All new relationships retain the original snapshot's assets, evidence and observations.

## Gate and limitations

Merge only after exact PR-head Linux locked formatting, check, strict Clippy, unit/integration/regression/security tests, docs/package, dependency policy/RustSec, semver, Windows and Rust 1.85 pass; resolve all actionable PR security findings before merge. FOSS-322 stays **In Progress**: common npm properties such as scripts/devDependencies/workspaces/optional dependency resolution remain deliberately unsupported; broad Cargo TOML, transitives, checkpoint semantics and dependency graph completeness are not provided by this increment.
