# Milestone B1 — opt-in collector fault isolation and safe diagnostics

Status: **unreleased implementation increment**. FOSS-369 is a bounded slice of FOSS-328 and does not change the Milestone A alpha package, `publish = false`, registry version, snapshot-v2 or the Collector wire contract.

## Contract and rationale

`collector::collect` and `orchestration::collect_normalized` keep their strict fail-fast behavior: a fatal `Collector::collect` error aborts the run. For a **cooperative, trusted in-process** collector that supports independent, explicit *single-source* invocations, choose `scope::collect_scoped_isolated` or `orchestration::collect_normalized_isolated`.

This explicit route validates the whole exact-source request, host-pinned collector descriptor, tenant identity, collection limits and OS capability grants **before** executing any collector code. It dispatches each source in lexicographic item order and records that source's outcome. Each collector call receives one requested source, not permission to traverse the root or inspect sibling inputs. An ordinary returned source-processing error discards observations from the failing source, emits a bounded typed diagnostic, and records `Failed` coverage. A specifically unsupported schema records `Unsupported` with the `UnsupportedSource` code, never a clean negative result. Successful sources retain observations and exact coverage. If an invoked collector returns success but omits source coverage and emits no observations, the attempted item is `Failed` with an `IncompleteScope` diagnostic; it is **not** falsely `NotInspected`. Sources never invoked after cancellation remain `NotInspected`. Source-specific `Partial` coverage with evidence survives.

Critically, a collector that calls `sink.emit`, `sink.cover` or `sink.diagnose` with a rejected event/source/invalid limit **poisons its per-source sink**. Even if the collector ignores the returned error, the isolation API returns a fatal error rather than downgrading a forged or out-of-scope write to a recoverable failure. Colliding cross-source event IDs, total run budgets and invalid host preflight also abort the run. Failures never become `InspectedNoObservation`. Neither route authenticates returned data as independently trustworthy.

The API is **not** suitable for stateful collectors whose interpretation depends on grouping multiple source items in one call. It is not an OS sandbox, retry engine, timeout facility, general-purpose source scanner or an automatic crash/panic guard. Isolate untrusted plugins in an external process and do not enable network access unless independently authorized. Cancellation is cooperative; once observed before the next source it stops dispatch and marks remaining items `NotInspected` with `Cancelled` diagnostics.

## Public usage

```rust
use cryptomap::{
    collector::CancellationToken,
    diagnostics::CollectionSummary,
    scope::collect_scoped_isolated,
};
// Construct `scope`, `collector` and `request` via the public host-granted
// CollectionScope/Collector/CollectionRequest APIs as shown in the examples.
// This is the raw evidence path; every output must still be normalized using
// independently trusted identity/scope and the canonical PipelineInput.
let outcome = collect_scoped_isolated(&scope, &collector, request, &CancellationToken::default())?;
let counts = CollectionSummary::from_outcome(&outcome);
assert_eq!(counts.requested, counts.attempted + counts.not_inspected);
```

For an immediately normalized and independently scope-verified snapshot, use `collect_normalized_isolated(ScopedInvocation { collector, input }, &cancel)` as tested in `tests/foss_369_isolation.rs`. Do not use a snapshot's digest alone as producer authentication.

`CollectionSummary` contains only counts: requested, attempted, observed/empty successes, partial, failed, unsupported, not inspected, observations and diagnostics. Unsupported sources count as attempted; only `NotInspected` is unattempted. The summary omits raw diagnostic strings, source identifiers and error payloads; `diagnostic_severity` and `retryable` provide stable typed classifications, **not** vulnerability severity or automatic retry permission. Existing canonical `CoverageRecord.reason_code` remains unchanged and generic; more detailed, schema-versioned reason projection is deferred to the parent FOSS-328 story.

## Regression and security acceptance

```shell
cargo test -p cryptomap --test foss_369_isolation --locked
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
```

The regression suite verifies two retained successes with one source failure, deterministic source ordering and summary serialization, host-grant preflight, forged/ignored sink emission, coverage and diagnostic writes, unsupported-schema classification, cross-source event collisions, aggregate budget failure, cancellation and normalized partial observation semantics, missing-coverage misclassification, secret-safe diagnostic handling, strict-mode compatibility and normalized snapshot integrity. Full CI also runs Rust 1.85, Windows, rustdoc, packaged external consumers, auditing, dependency policy and release gates.

B1 does not change the frozen Milestone A public compatibility vectors. Do not publish an alpha as a consequence of merging this PR.
