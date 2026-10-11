# FOSS-320.9 — Run-Scoped Evidence Source and Coverage Attestation

## Scope and threat boundary

FOSS-320.8 hardened canonical evidence timestamps. One remaining snapshot import vulnerability was that `InventoryBuilder::finalize` verified the evidence's collector/run and time, but not whether its **typed source identity** had been requested by the corresponding collector run or whether that source actually produced evidence-bearing coverage. An imported snapshot could previously carry `Telemetry:ungranted` or evidence for a source marked `NotInspected` and still recompute a canonical digest.

The incremental fix reuses the same public FOSS-2 inventory, coverage and verification API. Canonical evidence from the raw-to-normalization pipeline has a reviewed prefix `RawSourceKind:exact-item`, with exact kind tokens `Dependency`, `Certificate`, `TlsEndpoint`, `Source`, and `Telemetry`. `typed_evidence_item` strips only one recognized leading kind and the following colon, then compares **the entire remaining item** against `CollectionRun.requested`. A source string with internal colons is not split further. No suffix, substring, path, network or fuzzy matching is permitted.

After validating all typed coverage records, `InventoryBuilder::finalize` additionally requires every recognized typed evidence source to have coverage under the **same run and exact item**, and that coverage to be `InspectedObserved` or `Partial`. a `RunCompleteness::Failed` run, `Failed`, `Unsupported`, `NotInspected`, `InspectedNoObservation` source coverage, missing records, source substitution, and borrowed coverage from a different run are fail-closed `InventoryError::InvalidMetadata`. The existing pipeline/batch/stream orchestration already emits those records; no second normalizer is introduced. `InventorySnapshot::verify` and `from_json_verified` reconstruct through finalization and enforce this rule even for imported JSON. The snapshot schema version and identity/digest method are unchanged.

### Explicit migration boundary

Older FOSS-2 snapshots can have **unprefixed opaque evidence source labels**. Their source identity cannot be authenticated from this existing wire format. FOSS-320.9 deliberately preserves that legacy behavior without declaring such records positively attested. They must not gain new authority from an unrelated typed coverage record. A future versioned evidence-source structure and schema migration should address full coverage, rather than silently breaking deployed snapshot compatibility.

### Test-driven acceptance

- In-module unit tests: typed kind recognition, full colon-bearing source equality, negative suffix/prefix matching, legacy compatibility.
- `tests/source_attestation_contract.rs`: all five typed source kinds; verified JSON round-trip; out-of-scope/unrequested sources; partial coverage preservation; rejection of failed, unsupported, uninspected and explicitly no-observation states; missing run coverage; independently same-named sources across runs; JSON tampering; deterministic coverage permutations; legacy evidence compatibility.
- Regression gates include `pipeline_contract.rs`, `batch_contract.rs`, `stream_contract.rs`, `orchestration_contract.rs`, `correlation_contract.rs`, `snapshot_provenance_contract.rs`, and FOSS-2 model/property tests.
- CI: Rustfmt, locked strict Clippy and all-target check, workspace tests, rustdoc/package, RustSec audit and cargo-deny, SemVer, Windows compatibility and Rust 1.85 MSRV. Security review findings must be resolved on the exact final head before declaring merge-ready.

### Deliberately deferred

Implementing actual collectors (FOSS-322–326), checkpoint/restart persistence (FOSS-327), diagnostic taxonomy (FOSS-328), cryptographic attestation of collector execution, signing snapshot digests, historical migration of unprefixed evidence and arbitrary semantic relationship inference are outside this change. A stable digest alone is not a cryptographic signature.
