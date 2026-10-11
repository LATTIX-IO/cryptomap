# FOSS-320.8 — Canonical Snapshot Temporal Provenance Conformance

## Scope

FOSS-320.7 constrained incoming `RawObservation.observed_at` to the independently host-pinned collection interval in `pipeline::normalize`. FOSS-320.8 closes the **post-normalization trust boundary**: canonical snapshots created by `InventoryBuilder::finalize` or loaded through `InventorySnapshot::from_json_verified` must uphold the same invariant, even if they did not originate in a live collector invocation.

The check is implemented in the **existing** `InventoryBuilder::finalize` and therefore runs again when `InventorySnapshot::verify` reconstructs a snapshot from untrusted serialized data. Every evidence record must reference an existing collection run (pre-existing rule), match its collector ID/version (pre-existing rule) and have an RFC3339 timestamp whose **complete UTC instant, including every supported fractional digit**, lies **inclusively** between that run's validated start and end instants (new rule). A bad observation, malformed timestamp, or inverted interval prevents the entire snapshot from finalizing; no partial valid digest is returned. Equivalent timezone offsets are compared as UTC instants, not as strings. The bounded parser retains every accepted subsecond digit (up to the wire format's length limit); whole-second truncation is prohibited at both collection and snapshot boundaries.

No public snapshot schema fields, digest algorithm, canonical identity rules, algorithm registry, or collector APIs change. The rule applies equally to direct canonical builder usage, single-run normalized output, heterogeneous batch merges, round-tripped snapshots, and imported untrusted JSON. It does not claim a signed or trusted wall clock: callers must still anchor the run window independently of source data.

## Acceptance and threat tests

- In-module unit tests for inclusive UTC window, timezone offsets, fractional precision, malformed or inverted intervals and out-of-range observations.
- `tests/snapshot_provenance_contract.rs` exercises verified JSON round trips, past/future timestamps, fractional-second post-end/pre-start evidence, fractionally inverted empty run intervals, timezone-equivalent subsecond instants, tampered evidence and run windows, fail-closed multi-run snapshots, deterministic run permutation and legitimate partial-source coverage. `tests/temporal_finality_contract.rs` additionally checks live pipeline behavior at fractional boundaries.
- Existing `tests/temporal_finality_contract.rs`, `inventory.rs`, `model_contract.rs`, `properties.rs`, `pipeline_contract.rs`, `batch_contract.rs`, `stream_contract.rs` and `orchestration_contract.rs` must remain green.
- Out-of-run or invalid evidence timestamps fail with typed `InvalidTimestamp`. Inverted **run intervals** are rejected by `CollectionRun::validate` with `InvalidMetadata` (including empty runs); malformed run timestamps return `InvalidTimestamp`. Public pipeline errors must not echo raw event IDs. Recomputing a digest cannot bypass finalization validation.
- Verify exact PR head with Linux fmt, strict Clippy, locked workspace tests, rustdoc, package validation, cargo-audit/deny/semver; Windows compatibility and Rust 1.85 MSRV. Address review findings before merge.

## Boundaries

The consumer must **not** interpret source timestamps as a cryptographic proof of time, or infer absence of cryptography from incomplete coverage. FOSS-327 owns durable checkpoint/recovery, FOSS-328 owns comprehensive diagnostic taxonomy, and FOSS-322–326 own actual source collectors. Broad redefinition of provenance schema or incompatible snapshot migrations requires separate review.
