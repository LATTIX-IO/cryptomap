# FOSS-320.3: Explicit cross-source identity correlation and relationships

## Intent and trust boundary

This increment extends the same **host-pinned** `pipeline::normalize` path delivered in FOSS-320.1/.2; it does not create a second importer. All `RawObservation` records must first pass exact source authorization, run/collector identity validation, bounds, source coverage consistency and typed canonical normalization.

Cross-source **identity convergence** is deterministic: two independently collected certificate facts with the same SHA-256 DER fingerprint converge to the same canonical certificate asset, retaining both event/evidence identities. Ambiguous keys and source-site identities remain isolated by collection scope, provider instance and typed location.

Typed edges are created **only from an explicit collector assertion**. Place these two namespaced attributes on the *asserting* source event:

- `cryptomap:relation-kind`: one exact value from `uses_certificate`, `uses_key`, `uses_algorithm`, `depends_on`, `configured_for`
- `cryptomap:relation-target-event`: the exact `RawObservation.event_id` of the target fact from **the same host-pinned run and collector invocation**

Both keys must occur together. Target and source must be distinct, already-authorized, normalized events; dangling IDs and unknown kinds cause typed `InvalidOutcome` failure. An inferred evidence event cannot assert these direct relationships. Exact source-event matching does not search external systems, follow paths, parse hidden content, or join by similarly spelled names. An unused target certificate, key, dependency or library **cannot by itself imply a usage edge**.

## Relation matrix (source event -> target event)

| Raw source type | Required state | Relation | Required target type |
| --- | --- | --- | --- |
| Protocol | Negotiated | UsesCertificate | Certificate |
| Protocol | Negotiated | UsesKey | KeyReference |
| Protocol | Negotiated | UsesAlgorithm | AlgorithmUse |
| Protocol | Configured | ConfiguredFor | Configuration |
| Configuration | — | DependsOn | Dependency |

A `Configured` protocol cannot produce active `Uses*` edges. A `Configuration` record cannot be used to infer negotiation. The set is intentionally conservative, extensible only by a reviewed implementation and tests. Unsupported cross-kind assertions fail rather than being downgraded silently to generic `RelatedTo`.

## Provenance semantics

A relationship is an **assertion made by the source event** and is linked to that event's evidence ID. Merely observing the target asset is not independent corroboration of the edge; target evidence remains attached to its own observations. No inferred confidence boost is applied. Multiple explicit assertions of the same typed `(from, kind, to)` edge merge by the existing `RelationshipId::from_endpoints` identity and union distinct asserting evidence IDs. BTree-map ordered iteration ensures event permutation cannot affect graph identity or snapshot hash. Unsupported contradictory assertions fail typed validation; distinct supported assertions are preserved without erasing evidence.

## Acceptance verification

`crates/cryptomap/tests/correlation_contract.rs` covers exact cross-source links among negotiated TLS, certificate, provider-scoped key and algorithm assets; same-fingerprint canonical convergence without invented relationships; order invariance; partial-source evidence retention; deduped edge/evidence unions; configured-versus-negotiated rules; configuration/dependency semantics; missing/dangling/self/unknown and mismatched kind rejection; inferred relationship rejection; relationship budget overflows.

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --all-features --locked`, plus Windows and Rust 1.85 CI jobs.

## Explicitly deferred

No synonym matching, graph inference, semantic relationship guessing, claims of cryptographic strength, remote lookups or broad cross-run correlation. Future work includes richer typed attribute contracts and multi-collector reconciliation, conflict/diagnostic policy (FOSS-328), bounded streaming and cancellation, checkpoints and invalidation (FOSS-327), and production collector adapters (FOSS-322 through FOSS-326). Do not close parent FOSS-320 solely from this increment.
