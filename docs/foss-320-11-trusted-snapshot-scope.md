# FOSS-320.11 — Trusted scope verification for imported snapshots

## Threat and scope

FOSS-320.10 prevents mixing tenants inside a canonical snapshot, but an internally valid snapshot can still claim one arbitrary tenant. Consumers must compare a validated snapshot against the scope resolved by the host's authorization layer, rather than trusting a serialized run claim. This increment adds two additive APIs to `InventorySnapshot` without changing the v2 schema, digest or ingestion behavior.

- `verify_for_scope(expected_scope, limits)` validates all previous canonical invariants first, requires at least one collection run, and then requires every run to match the host-provided `CollectionScopeId`.
- `from_json_verified_for_scope(input, expected_scope, limits)` preserves the existing bounded, strict JSON parsing and digest checks, then binds the result to the expected scope.
- The legacy zero-run snapshot still verifies under `verify`, but fails the new authorized consumer API because it cannot establish scope provenance.

The expected scope must be obtained independently from an authorized host request. Calling this API with a value copied out of untrusted JSON defeats the purpose. Scope equality is not a cryptographic signature and cannot independently establish provenance, collector authenticity or tenant authentication.

## Acceptance

`crates/cryptomap/tests/trusted_snapshot_scope_contract.rs` verifies same-scope multi-run success and roundtrip, internally valid foreign-tenant denial with sanitized error, runless legacy denial under the opt-in API, digest tampering rejection, JSON duplicate-key denial and enforced input size limits. Existing snapshot, provenance, typed evidence, orchestration and batch tests must remain green.

Required merge gate: exact-head Linux locked format/check, strict Clippy, unit/integration/regression tests, rustdoc, package and dependency security checks, Windows compatibility, Rust 1.85 MSRV, with all actionable review findings resolved. No early merge.

## Non-goals

No identity signatures, remote trust anchors, authenticated collector proofs, schema migration, hidden collection or cross-tenant querying. FOSS-320 remains in progress pending parent-level acceptance.
