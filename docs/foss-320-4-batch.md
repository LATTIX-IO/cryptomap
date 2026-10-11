# FOSS-320.4 — Bounded Multi-Collector Normalization and Reconciliation

## Contract

`cryptomap::batch::normalize_batch(Vec<BatchRun>, BatchLimits)` accepts independently host-pinned `PipelineInput` plus `CollectionOutcome` per run. This is not a new collector, network reader or alternate normalization path: **each run passes the existing `pipeline::normalize` implementation first**. The aggregate then merges validated canonical assets, observations, evidence, run records and typed relationships through the existing `InventoryBuilder`.

`BatchLimits` controls the maximum runs, total requested sources, total raw observation records, total serialized raw bytes and final `InventoryLimits` including assets, evidence, relationships, runs and snapshot bytes. The batch performs a **preflight pass before building any assets**: host-pinned collector/run equality, distinct run IDs, one administrative/tenant scope, exact per-run source grants, individual `CollectionRequest` validity, raw record validation, and checked aggregate counters. It rejects zero/invalid budgets, oversized aggregate inputs, foreign administrative scopes and duplicate run IDs. It never infers a missing grant from an outcome.

## Reconciliation semantics

- Different collector IDs can report the same source label. `CoverageRecord {run,source_item}` is authoritative. The legacy flat `coverage` map uses a domain-separated hash of the typed `(run,source)` JSON tuple, preventing overwrite or separator ambiguity; consumers should use typed coverage records.
- Independent observations from different runs retain the original evidence, source, collector, version and run IDs, even when both converge on the same canonical asset (e.g. a certificate with an identical public SHA-256 DER fingerprint).
- Repeated supported relationships merge by canonical direction/type/endpoints and union the *asserting* evidence. No relationship is inferred across runs and a raw relation target event cannot reference another run: the existing single-run correlation gate rejects dangling references.
- Run processing order is sorted by trusted `CollectionRunId`. All canonical maps are deterministic and the finalized snapshot ID is stable under permutation of collector completion order.
- A valid failed collector or partially completed source contributes an explicit run and coverage outcome; successful evidence from other runs is not erased. A **structurally invalid, forged, unauthorized or budget-violating** outcome rejects the entire batch atomically rather than masquerading as an ordinary collection failure.
- A canonical identity collision with contradictory asset metadata fails closed; all independent immutable observations are preserved when identity and evidence validation succeed. The batch does not claim that two similarly named identifiers are the same key, certificate, or runtime use.

## Test-driven acceptance

`crates/cryptomap/tests/batch_contract.rs` covers: two heterogeneous collectors with the same source label, exact certificate convergence without evidence loss, identical event IDs across separate collector/run contexts, deterministic permutations and snapshot verification, complete/partial/failed runs, malformed failed coverage, cross-tenant rejection, duplicate run ID rejection, forged collector/run, source tampering, bounded run/source/observation/raw-byte/evidence accumulation and a forbidden cross-run relation target.

The merge gate is `cargo fmt --all -- --check`, strict workspace Clippy, all workspace unit/integration tests, Rust 1.85 MSRV and Windows compatibility CI on the exact commit, plus no outstanding review findings.

## Deferred work

This increment processes completed `CollectionOutcome` values, not streaming live collectors. Backpressure/cancellation, incremental/checkpoint replay and source re-inspection scheduling are separate future concerns (FOSS-327). A richer partial-failure and diagnostic taxonomy is FOSS-328. Actual collector backends are FOSS-322—326. No cross-tenant batch, background scanning, semantic graph inference or implicit external I/O is introduced.
