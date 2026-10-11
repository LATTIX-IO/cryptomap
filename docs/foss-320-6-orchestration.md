# FOSS-320.6 — Host-Pinned Collector Orchestration and End-to-End Conformance

## Goal

Provide a direct, end-to-end integration path for independent Rust `Collector` implementations: explicit host-approved source manifest → collector execution through the existing `CollectionSink` → validated `CollectionOutcome` → the existing `pipeline::normalize` and `batch::normalize_batch` → verified canonical `InventorySnapshot`. Do not add a parallel ingestion, identity scheme, snapshot builder, network fetch, or platform collector.

## Public integration API

- `orchestration::ScopedInvocation { collector: &dyn Collector, input: PipelineInput }`: a trusted host must separately pin `CollectionScope`, `IdentityContext`, expected descriptor/version/run, exact source list, raw and snapshot limits, algorithm registry and run timestamps.
- `collect_normalized(invocation, &CancellationToken)`: verifies identity-scope equality, *independent host-pinned descriptor equality*, request compatibility and exact source grants **before any call to `Collector::collect`**. Calls the existing `collect_scoped` and `normalize` rather than importing unverified JSON directly.
- `collect_normalized_batch(invocations, BatchLimits, &CancellationToken)`: validates **all** invocations before executing any collector, including common tenant scope, distinct trusted run IDs, per-collector capabilities/permissions, exact authorized sources and checked aggregate run/source budgets. Sorts by host-pinned run identity, calls the same collector/sink path and passes the independently validated outcomes through existing `normalize_batch`. That batch also enforces aggregate raw observations/serialized bytes and canonical snapshot limits, preserves run-specific coverage, merges exact canonical identities and only explicit supported relationships.

No user-provided raw fact, collector descriptor, run ID or source-name hint is allowed to escalate collection scope. A collector may return a legitimate Failed/Partial outcome: preserve it as coverage evidence, not as an empty successful collection. A structural contract violation or fatal collector error fails closed, producing no canonical batch.

**Security boundary:** This invokes *trusted in-process Rust code*. It cannot sandbox a malicious plugin that independently invokes ambient OS APIs. For untrusted collectors, use OS isolation and FOSS-319 file/network capability adapters; this wrapper is not a sandbox.

## Unit, integration, regression and security requirements

`crates/cryptomap/tests/orchestration_contract.rs` implements a minimal independent `Collector`, not a built-in backend or a crafted `CollectionOutcome`, validating:

1. Real collector → canonical asset/evidence/source coverage and `Snapshot::verify`; explicitly negotiated protocol → evidence-backed certificate relationship.
2. Two heterogeneous authorized collectors → deterministic merged snapshots on reversed invocation order, independent run/evidence provenance and no cross-tenant merger.
3. Partial/failed state remains partial; cancellation before execution skips collector code and produces NotInspected coverage; cooperatively cancelled source does not claim complete inspection.
4. Batch-wide **preflight before any invocation** for wrong tenant, duplicate run, forged collector descriptor, ungranted source and aggregate run/source budgets. Record a per-collector call count to prove zero source inspection, not merely an error returned after work.
5. Untrusted collector emitting a forged run or ungranted source, conflicting replay, or fatal collector error must not yield a canonical snapshot.

Acceptance requires exact-head `cargo fmt --all -- --check`, `cargo check --workspace --all-targets --all-features --locked`, strict Clippy `-D warnings`, locked workspace tests, rustdoc with `-D warnings`, package verification, RustSec dependency audit, cargo-deny policy, semver checks, Windows compatibility and Rust 1.85 MSRV via CI; no unresolved findings.

## Explicit exclusions

Actual dependency, source, certificate, network, or telemetry collector backends (FOSS-322–326), durable checkpoints (FOSS-327), detailed fault taxonomy (FOSS-328), constant-memory streaming normalization, security posture scoring, compliance findings and implicit discovery are not part of this increment. Public collector orchestration does not authorize additional I/O. Keep parent FOSS-320 In Progress pending broader acceptance and integration review.
