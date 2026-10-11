# FOSS-320.10 — Single-Scope Canonical Snapshot Isolation

## Scope and rationale

`pipeline::normalize` already uses a host-pinned `CollectionScope`; `batch::normalize_batch` and `orchestration::collect_normalized_batch` independently prevent cross-tenant batches. However, callers could bypass those entrypoints by constructing an `InventoryBuilder` or importing a serialized snapshot containing runs from multiple administrative scopes, then recomputing a semantically valid digest. The existing `InventorySnapshot::verify` was only enforcing per-run collector, source, temporal and coverage invariants.

A canonical `InventorySnapshot` now contains runs from **exactly one** `CollectionScopeId`, or no runs for legacy empty/unscoped snapshots. `InventoryBuilder::finalize` validates all `CollectionRun.scope` values before mapping evidence or producing a digest. `InventorySnapshot::verify` and `from_json_verified` independently re-finalize imported snapshots and inherit this rule. Rejection is a typed, sanitized `InventoryError::InvalidMetadata` with no tenant names in the public error. The empty, historical, runless snapshot and same-scope multi-run reconciliation remain supported. No schema version, canonical asset identity, hash derivation, source authorizations or I/O contracts change.

This is a defense-in-depth integrity check, not a substitute for enforcing tenant authentication or cryptographic signatures at the ingest boundary: a forged snapshot that *only* contains a single attacker-asserted scope requires external authentication, integrity proof or a host-supplied expected scope to detect. Mixed-scope rejection is a necessary, not sufficient, authorization guarantee.

## Acceptance contract and test-driven development

1. **Unit:** `lib.rs::snapshot_scope_unit_tests` ensures zero-run/legacy compatibility, valid same-scope multi-run finalization and rejection of two different `CollectionScopeId` values.
2. **Regression:** `tests/snapshot_scope_contract.rs` covers deterministic run permutation, one-tenant roundtrip, two tenants with independently valid evidence and partial coverage, and mixed-tenant snapshots even with no evidence. Existing `batch_contract.rs`, `orchestration_contract.rs`, `snapshot_provenance_contract.rs`, `source_attestation_contract.rs` and `pipeline_contract.rs` must remain green.
3. **Security:** Tamper only one `CollectionRun.scope` in a valid multi-run snapshot. Both `InventorySnapshot::verify` and `from_json_verified` must reject before a new canonical digest can be issued. Public diagnostics must not expose either tenant name. A valid single-scope source retains partial evidence (no false absence).
4. **CI:** Linux formatting, all-target locked check, strict Clippy warnings-as-errors, locked workspace tests, rustdoc, package and dependency audit/policy/semver; Windows compatibility; Rust 1.85 MSRV on the exact final PR head. Address unresolved security reviews before merging.

## Explicit exclusions

No new collector, remote fetch, canonical snapshot schema migration, tenant identity provider, trusted-run signature, checkpoint/recovery (FOSS-327) or expanded diagnostics (FOSS-328). FOSS-320 retains its parent SDD acceptance checks, while FOSS-322–326 are separate collector implementation stories.
