# FOSS-322.11 — Verified incremental npm collection plan

## Purpose and API

`plan_npm_incremental(checkpoint, snapshot, scope, raw_limits, inventory_limits)` is an opt-in, deterministic, **point-in-time advisory planner** for an already canonicalized npm dependency snapshot.

It returns one of two serializable decisions:

- `NpmIncrementalPlan::ReuseVerified { snapshot_id }`: both current files are independently authorized, still hash identically to the existing versioned checkpoint, and `verify_npm_checkpoint` has verified the full canonical snapshot, complete-run source evidence, exact path-scoped installation graph and source provenance. This permits the caller to reuse an existing *already verified* immutable snapshot instead of invoking collectors, normalization or persistence again.
- `NpmIncrementalPlan::Recollect { manifest_changed, lock_changed }`: one or both explicitly authorized source files have changed. Both sources must be recollected and the graph reprojected before minting another checkpoint; this is **not** an authorization to reuse evidence or a claim that the new documents are semantically valid.

## Security and consistency

The planner rejects invalid `RawLimits`, incorrectly scoped or noncanonical snapshots, unsupported/altered checkpoint metadata, modified fingerprint, source-item aliasing and tenant mismatches **before** reading new source content. File acquisition uses only two exact existing `CollectionScope` capabilities with bounded reads and checked aggregate input bytes. An ungranted file or excessive budget is an error, never a synthetic `Recollect` or `ReuseVerified` outcome.

The checkpoint fingerprint is an unkeyed SHA-256 integrity checksum, **not a cryptographic signature**. The reuse path never relies on the checksum alone: fresh files, complete independently persisted collector evidence, exact installation assets and canonical dependencies must pass the existing full revalidator. This intentionally trades some CPU for correctness while avoiding repeated collection/normalization. A maliciously forged cache or stale/cross-tenant snapshot must never produce the reuse decision.

The API is not a filesystem watcher, event-driven invalidation daemon, change-stream processor or resumable scan executor. Freshness is point-in-time; hosts requiring concurrency guarantees must control source mutations between validation and use. It does not execute npm, fetch network resources, infer algorithm use, modify canonical schema, or persist any new package evidence.

## Test-driven acceptance

- Unit/functional contracts: two identical planner invocations yield the same `ReuseVerified` decision and snapshot ID, stable JSON serialization, and unchanged collection/reprojection.
- Regression: changing just the manifest yields `Recollect(true,false)`, changing just the lock yields `Recollect(false,true)`, and changing both yields `Recollect(true,true)`; no stale canonical snapshot can be checkpointed afterward.
- Security/negative: fingerprint tampering, checkpoint hash tampering, corrupted snapshot assets, foreign tenant, denied manifest file grant, invalid resource limits, and aggregate source-byte exhaustion deny reuse.
- All prior FOSS-322.6 through .10 security, Windows and MSRV suites remain intact.
- **Merge gates:** exact final PR-head GitHub Actions Linux formatting, locked compilation, strict Clippy, unit/integration/regression/security tests, docs/package/RustSec/dependency policy/SemVer; Windows, Rust 1.85 MSRV and resolved actionable review threads.

## Explicitly deferred

A later increment must implement bounded resumable scan execution and atomic generation swaps (ensuring readers never observe mixed-generation evidence). Broader npm/Cargo semantic support remains outside this incremental planner. FOSS-322 parent remains In Progress.
