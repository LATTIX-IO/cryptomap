# FOSS-320.7 — Host-Bound Temporal Provenance and Terminal Source Finality

## Design requirement

Cryptomap MUST distinguish **when a collector claims a fact was observed** from an arbitrary timestamp supplied in its raw record, and MUST treat a collector's terminal source coverage as a final statement for that run. This increment strengthens existing contracts without creating a new normalization path, platform collector, storage layer, or diagnostic taxonomy.

### Host-anchored observation time

`pipeline::normalize(PipelineInput, CollectionOutcome)` uses `PipelineInput.started_at` and `ended_at` as independently host-pinned collection boundaries. After per-record `RawObservation::validate` and before identity or evidence insertion, it parses the record's `observed_at` with the existing strict RFC3339 `validation::utc_seconds` routine. Records whose UTC instant is outside **the inclusive host interval** fail closed with `PipelineError::Inventory(InvalidTimestamp)`; inverted and malformed host windows are rejected even for empty runs. Equivalent RFC3339 offsets resolve to the same instant and are accepted. Invalid records cannot produce a partly normalized snapshot, relationship or inferred cryptographic use.

`observed_at` represents the time **this collector observed the fact**, not the certificate's validity date, source-file modification timestamp, or time an original log event occurred. Collectors that inspect historical logs must record the collection observation time in `observed_at`, and may retain separately typed historical event dates only under a future reviewed contract. The temporal bound must never be based on the untrusted source's clock.

Limitations: UTC-second parsing ignores fractional subsecond precision, matching the existing validated schema; this is NOT proof of trusted clock hardware, non-repudiation, or trusted execution.

### Source finality and replay

After `CollectionSink::cover(source_item, state)` records any terminal coverage state, `CollectionSink::emit` rejects **all later observations** for that item, including identical replays, with a typed `InvalidMetadata` failure before mutation. This closes a time-of-check/time-of-use semantic boundary: a collector cannot mark a source complete/failed/unsupported and then extend that source's facts. Double terminal coverage was already rejected. Previously accepted facts remain unmodified. `StreamIntake::cover` already drains accepted pending facts before sealing and continues to enforce the same finality policy. Terminal source coverage is an assertion from a trusted collector, not proof that an independent operating system sandbox has completed I/O.

### Validation requirements

`tests/temporal_finality_contract.rs` covers:
- Unit-level boundary and RFC3339 UTC-offset acceptance; negative before-start/after-end records and invalid/inverted host windows, including empty collection runs.
- A two-collector batch with one forged timestamp rejected atomically (no partially authorized snapshot).
- All terminal coverage states sealed against subsequent unique or replay facts, and duplicate coverage rejected.
- Real external Rust `Collector` asserting coverage and then emitting another fact rejected through `orchestration::collect_normalized`, with no canonical output.
- Public error `Debug` redacts untrusted event IDs and historical fields remain no-op for cryptographic inference.
- Existing `stream_contract.rs`, `orchestration_contract.rs`, `pipeline_contract.rs`, `batch_contract.rs` and `correlation_contract.rs` must continue to pass.

Exact PR-head CI gates: `cargo fmt --all -- --check`; `cargo check --workspace --all-targets --all-features --locked`; strict `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`; `cargo test --workspace --all-features --locked`; rustdoc warnings-as-errors; package, RustSec, dependency policy and semver checks; Windows tests; Rust 1.85 MSRV. Do not merge with unresolved review findings.

## Scope boundary

This is a provenance and lifecycle hardening increment of FOSS-320, **not** persistence/checkpoints (FOSS-327), broad diagnostic/fault taxonomy (FOSS-328), new collectors (FOSS-322–326), or cryptographic compliance advice. Untrusted collectors must still run in an OS sandbox to constrain ambient I/O; Rust APIs cannot impose that sandbox on third-party code.
