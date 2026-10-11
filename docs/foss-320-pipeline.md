# FOSS-320 Increment 1: scoped raw-to-canonical pipeline

The initial `cryptomap::pipeline::normalize` entry point transforms an explicitly authorized `CollectionOutcome` into a verified `InventorySnapshot` using the existing canonical FOSS-2 builder and versioned FOSS-321 algorithm registry. This is a **bounded vertical slice**, not the completed FOSS-320 story.

## Trust contract

The host supplies a `CollectionScope` containing independently granted exact source items, an `IdentityContext` with the **same scope identifier**, the exact `RequestedSource` list, `RawLimits`, `InventoryLimits`, registry, and collection-run timestamps. The function repeats `CollectionRequest` validation, scope authorization, per-record raw validation and budget enforcement. Source item, kind, collector version and run IDs must match the host request. Collector results cannot grant themselves permissions by claiming new source IDs or asserting a different tenant.

Only `RawFactKind::AlgorithmUse` and `RawFactKind::Dependency` are mapped during this increment. Other categories produce a typed `UnsupportedFact` error, not partial silent data loss. Algorithm-use records must supply exact `cryptomap:algorithm-namespace` and `cryptomap:algorithm-kind` attributes compatible with the FOSS-321 registry; identifiers are never classified by fuzzy matching. Both raw and normalized names, rule and source reference remain evidence-linked observations. Unknowns retain the namespaced identifier instead of being assigned a false known profile. Source parameters are carried forward without claiming that ASN.1/mode/size semantics have been validated.

Dependency facts produce `AssetKind::Library` and a `dependency:presence=declared` observation. A dependency does not prove algorithm invocation, configuration or negotiation. Evidence preserves the original collector confidence; registry exact matching does not increase that confidence.

## Determinism and collection fidelity

Every input event is checked before insertion, then replay identity is sorted with a `BTreeMap`; conflicting duplicate event IDs fail. Typed IDs are derived from domain-separated SHA-256 hashes of JSON tuples, so source string concatenation cannot cause ID ambiguity. Independent source events use distinct observation contexts to avoid manufacturing contradictory-value conflicts solely because of alias differences.

The pipeline rejects disagreement between emitted observations and source coverage or aggregate status. Failures and uninspected sources retain exact `CoverageRecord` values, with `RunCompleteness::Partial` or `Failed`; one failed source does not erase a separate successful source. Snapshot finalization invokes existing asset, reference, evidence, timestamp, quota, and digest checks.

## Acceptance verification

Run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --test pipeline_contract --locked
cargo test --workspace --all-features --locked
```

Integration fixtures cover approved algorithm records, exact canonical profiles and raw provenance, replay-permutation invariance, unknown-safe handling, out-of-scope attempts, contradictory collection states, conflicting replay, unsupported fact types, tenant identity isolation, failed-source partial coverage and noninferential dependency presence. Required CI additionally includes Windows, Rust 1.85, docs and dependency/security gates.

## Follow-on increments

Next: typed normalization of certificate, key reference, protocol and configuration observations; parameter parsing and richer identity correlation; evidence/conflict semantics and explicit partial-source diagnostics; limits across multi-collector orchestration; cancellation and streaming/backpressure. Host-enforced operating-system isolation remains necessary for hostile third-party collector code. Neither registry matching nor the resulting snapshot makes cryptographic strength or compliance judgments.
