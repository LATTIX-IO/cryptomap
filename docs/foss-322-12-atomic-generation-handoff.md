# FOSS-322.12 — Atomic in-memory npm generation handoff

## Objective

Prevent readers from accidentally combining a checkpoint from one inventory scan with an inventory snapshot from another, while blocking stale concurrent writers and requiring full source/evidence revalidation before publication.

This increment follows the source-bound checkpoint (FOSS-322.10) and verified incremental reuse planner (FOSS-322.11).

## Interfaces

- \`NpmGenerationStore::new(scope, manifest_item, lock_item)\`: tenant- and source-pair-bound in-memory store. Both source identifiers must be distinct, nonempty and bounded. No grant is inherited by construction.
- \`publish(checkpoint, snapshot, scope, expected_sequence, raw_limits, inventory_limits)\`: full \`verify_npm_checkpoint\` must succeed before the mutex is acquired. \`expected_sequence\` is \`None\` on an empty store and the observed \`Some(sequence)\` when replacing an existing generation. Under the mutex, a stale sequence rejects publication. A successful call swaps one \`Arc<NpmVerifiedGeneration>\` atomically and advances the local sequence.
- \`current()\`: returns one \`Arc\` containing the immutable canonical snapshot, the exact validated checkpoint and a monotonically increasing local sequence. A reader holding an old \`Arc\` continues to see the old coherent pair after a replacement. Lock poisoning fails closed.
- \`NpmVerifiedGeneration::{sequence,snapshot,checkpoint}\`: read-only views of one published generation.

## Correctness and security contract

1. No partial graph, unpublished checkpoint, cross-tenant snapshot or ungranted source is publishable. The existing verifier checks file authorization and bounded manifest/lock reads, complete persisted independent source evidence, all canonical graph relationships and snapshot integrity. An unkeyed checkpoint checksum alone is never an authorization.
2. A competing writer with a stale expected generation never overwrites the winner. Sequence wraparound fails instead of resetting.
3. Verification failures, poisoned lock state and sequence conflicts leave the previously published generation unchanged.
4. The critical section contains only the compare-and-swap pointer swap; expensive source and canonical graph verification occurs outside it.
5. The store is process-local, not persistent or replicated. This does **not** implement a filesystem transaction, file watcher, resumable parser, automatically scheduled rescans or storage-atomic checkpoint disk writes. File changes between source revalidation and publication remain a caller-controlled TOCTOU risk. Readers needing live-source freshness should re-run the prior incremental planner or use host-controlled file-write exclusion. An immutable snapshot is a point-in-time observation.
6. No network access, package scripts, npm execution, global filesystem discovery, fabricated runtime algorithm-use evidence or public snapshot schema changes.

## Acceptance and test matrix

- **Unit:** invalid/duplicate/oversized source identifiers cannot construct a store; valid named source pair is accepted without implicit file reads.
- **Integration:** initial empty state; successful publish; pointer-consistent checkpoint/snapshot; subsequent generation swap; holding the first \`Arc\` preserves its original generation; monotonically increasing sequence.
- **Regression:** stale expected sequence cannot overwrite current state; two concurrent writers starting with identical expected state produce one success, one conflict, and one coherent published pair.
- **Security:** tampered fingerprint, poisoned canonical asset metadata, wrong tenant, absent manifest grant and changed manifest source are rejected; publication errors do not mutate the store.
- **Required CI before merge:** final PR-head Linux stable formatting/locked check/Clippy \`-D warnings\`/unit+integration+regression+security/tests/docs/package/RustSec audit/dependency policy/SemVer; Windows locked check/tests; Rust 1.85 locked check/tests; all actionable review threads resolved.

## Deferred

FOSS-322 remains In Progress. A subsequent increment needs bounded resumable scan execution and durable/atomic persistence, with host-owned mutation exclusion or a stable source-generation capability. Cargo/npm grammar and unsupported dependency profiles remain conservative and fail-closed.
