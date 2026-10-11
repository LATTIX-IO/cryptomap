# FOSS-322.4 — Evidence-bound canonical Cargo direct edges

## Scope

The opt-in public Cargo projector, `collectors::dependency::projection::project_cargo_direct_edges`, takes a verified canonical snapshot, trusted tenant-specific `CollectionScope`, two exact authorized source item IDs (`Cargo.toml` and `Cargo.lock`), `RawLimits`, and `InventoryLimits`. It re-runs the previously merged strict Cargo exact-pin manifest/lockfile reconciliation (FOSS-322.3) from host-granted file capabilities before projecting any edge.

The returned new, finalized canonical `InventorySnapshot` preserves all existing assets, evidence, observations, runs, and coverage, and adds only deterministic `RelationshipKind::DependsOn` entries. No runtime algorithm-use inference, Cargo command execution, package build script, implicit filesystem traversal, network fetch or new collector.

## Evidence and security invariants

- Verify canonical digest, schema, source references and tenant scope against the host `scope.id()` before performing reconciliation.
- Root and target must **already be canonical Cargo Library assets** at the trusted tenant scope. No missing package identities may be invented or guessed from names.
- For each edge, root and target must each have an existing `dependency:presence = declared` observation, tied to `cryptomap:cargo-lockfile`, `EvidenceKind::Direct`, `Confidence::Confirmed`, exactly `Dependency:<lock_item>`, the freshly recomputed lockfile SHA-256, a successful `InspectedObserved` coverage record, and **at least one common collection run**. Edge references the union of those existing evidence IDs for common runs.
- All edges are proved before building the projected snapshot, and canonical finalization and host-scope verification are repeated after projection. Stale/missing/forged source identities or digest, partial/failed coverage, mixed tenants, unrelated runs and missing assets return sanitized `UnboundEvidence`; no partial result.
- An explicit relationship-count limit is checked before rebuilding. Repeated projections are deterministic/idempotent, preserving canonical identities.
- The manifest is reauthorized and parsed on every call but **no separate manifest Evidence is added** to the canonical snapshot. The relationship's evidence IDs reference lockfile package-presence observations; the manifest confirmation is an execution precondition only. Full serialized dual-source evidence and complete TOML support require subsequent FOSS-322 increments.
- Strict exact pins, unique matching Cargo.lock packages and root dependency declarations only. Unsupported Cargo manifests/ambiguous or optional dependencies remain fail-closed under the prior scope contract.

## Acceptance tests

`tests/cargo_direct_projection_contract.rs` covers: actual scoped filesystem grant and `collect_normalized` path; one exact-pinned link from same-run Cargo evidence; deterministic/idempotent canonical replay; unchanged assets and observations; per-endpoint evidence ID linkage and verified snapshot digest; credential redaction; cross-tenant denial; missing manifest grant denial; same-name evidence from another source item denial; stale source digest denial; tampered canonical input denial; ambiguous package version denial; and relationship-budget enforcement.

Required merge gates: exact-head Linux locked format, check, strict Clippy, unit/integration/regression tests, rustdoc, cargo package, RustSec and cargo-deny, semver; Windows compatibility; Rust 1.85; no unresolved actionable security-review threads. The parent FOSS-322 remains **In Progress** pending manifest Evidence persistence, Cargo TOML breadth, npm package.json reconciliation, dependency graph completeness and checkpoints.
