# FOSS-320.5 — Bounded Intake, Backpressure, Cooperative Cancellation

## Problem and implementation boundary

Previously `CollectionSink` accepted and accumulated validated `RawObservation` records, but no consumer-facing bounded intermediate window or explicit backpressure contract existed. The established `CollectionSink::finish`/ `pipeline::normalize` path is preserved. This increment adds `stream::StreamIntake` as an optional, runtime-independent front end. No new canonical identity derivation, source access or graph inference is introduced.

Host setup: obtain a `CollectionScope` with exact file/network/logical grants; provide a host-trusted `CollectorDescriptor`, `CollectionRequest`, cloneable `CancellationToken`, and `WindowLimits {records, bytes}`. `StreamIntake::new` checks descriptor, request and independently caller-granted scope **before** accepting events. Windows cannot exceed per-run `RawLimits`. `try_push(&RawObservation)` validates raw schema, bounded source locator, collector identity/version/run and exact authorized kind+item on every record, then copies only the bounded, accepted event. It holds no OS handles or credentials and initiates no ambient I/O. Untrusted third-party collector code still requires OS process sandboxing.

## Delivery API

1. `try_push(&record) -> Result<(),StreamError>`. Identical pending replays are idempotent; contradictory same-ID facts fail. When records/bytes reach the high-water mark, `Backpressure` is returned **without mutating state**; the caller still owns its borrowed record and must retry it after draining. An event larger than an empty window returns typed `LimitExceeded` (never endless backpressure). No event may be admitted to a source whose terminal coverage was recorded.
2. `drain() -> Result<usize,StreamError>`. Commits pending records in sorted event-ID order through the existing `CollectionSink::emit`. The sink enforces final per-run count and byte limits and cross-window replay consistency. On failure, the intake is poisoned and can never produce an apparently valid terminal outcome. Independent window capacity is reset only on success. Draining is synchronous and caller-demand-driven; there are no implicit threads, polling or unbounded queues.
3. `cover(source,state)`. Validates that the source was requested, flushes pending evidence, records source terminal state once, and prevents subsequent admission for that source. Denies new coverage following cooperative cancellation.
4. `finish() -> Result<CollectionOutcome,StreamError>`. Always flushes **already admitted** pending records even when cancellation occurs. Open sources with observations become `CoverageState::Partial`; open unseen sources become `NotInspected`. Cancellation adds bounded `CollectorDiagnosticCode::Cancelled` per unfinished source. Previously completed sources retain their legitimate terminal states. The underlying `CollectionSink::finish` determines `Complete`, `Partial` or `Failed` status. Partial-source evidence is not mislabeled invalid by the sink.
5. Pass the `CollectionOutcome` to **existing** `pipeline::normalize` with host-pinned descriptor/run/identity and authorized scope, or to `batch::normalize_batch` for reconciled multi-run snapshots. This repeats independent provenance, raw-limit and coverage validation, and uses FOSS-320.1–.4's canonical evidence and snapshot builder.

A producer must cooperatively check `CancellationToken` while performing work. `try_push` makes admission cancellation-aware; it cannot forcibly interrupt a blocking third-party collector or prevent ambient I/O outside the capability API.

## Fault and replay policy

Malformed source IDs, foreign collector/run, prohibited raw secret markers, invalid schema and inconsistent replay IDs cause sanitized typed failures. Buffer full is a recoverable flow-control signal, distinct from a record that can never fit. Cross-window duplicates preserve a single canonical event; conflicting later replays poison the intake and prevent terminal materialization. A valid interrupted collection does not imply no cryptographic use; already accepted observations survive with Partial coverage.

The system stores raw observations up to the caller's per-run `RawLimits` in `CollectionSink` prior to normalization. Window buffering is bounded; **this does not yet implement O(1)-memory streaming snapshot construction**. That would require a separately reviewed persisted/staged canonical builder or spill-to-disk contract. The ownership, cancellation and quota semantics here provide the incremental intake contract without misrepresenting resource characteristics.

## Test driven acceptance

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --all-features --locked` and complete CI on Linux, Windows, Rust 1.85.

`crates/cryptomap/tests/stream_contract.rs` tests record/byte high-water marks, borrowed-record retry with no mutation, too-large event fail-fast, identical replay within/across windows, conflicting replay fail-closed poison, cancellation before first item and mid-source (including already accepted undrained evidence), cancellation after one completed source, deterministic canonical snapshot under different chunk boundaries and event ordering, foreign source/run/collector and secret-byte rejection, ungranted scopes, invalid window configuration and rejection after terminal coverage. The existing `collector_contract.rs` and `pipeline_contract.rs` continue to protect legacy collector and normalization behavior.

## Scope exclusions and follow-on

No background task scheduling, durable checkpoint serialization or replay after a process crash (FOSS-327); no large diagnostic taxonomy or fault policy coordinator (FOSS-328); no actual dependency, X.509, network, source-code or telemetry backend (FOSS-322–326). Do not introduce unapproved network access, unbounded queue growth, key material retention, assumptions that configured crypto was negotiated, or false assurance claims.
