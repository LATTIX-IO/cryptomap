# cryptomap

Evidence-backed Rust cryptographic inventory: typed assets, evidence, scoped collection runs, canonical identity, deterministic snapshots, query and change detection.

## Architecture

cryptomap stores **observed facts**. It does not execute cryptography, decide policy compliance, or plan post-quantum migration. Its downstream consumers are cryptopolicy and cryptoshift.

- Asset: canonical logical object/use.
- Observation: immutable, evidence-backed assertion about one asset.
- Evidence: collector/run/source/timestamp and direct/inferred confidence.
- CollectionRun and CoverageRecord: explicit attempted scope and completion.
- InventorySnapshot: sorted, SHA-256-bound serialized state; use `from_json_verified` when importing untrusted data.
- ChangeSet: asset, observation, evidence/confidence, relationship, conflict and coverage deltas. Apparent removal after partial collection is **tentative**, not confirmed.

## Quickstart

```rust
use cryptomap::{AssetKind, IdentityContext, InventoryBuilder, InventoryLimits};
use std::collections::BTreeMap;

let context = IdentityContext::new("enterprise-prod").unwrap();
let mut builder = InventoryBuilder::new();
let key = builder.ingest_candidate(
    AssetKind::Library {
        ecosystem: "cargo".into(),
        name: "openssl".into(),
        version: "3.0.0".into(),
    },
    &context,
    BTreeMap::new(),
).unwrap();

let snapshot = builder.finalize(InventoryLimits::default()).unwrap();
snapshot.verify(InventoryLimits::default()).unwrap();
assert!(snapshot.assets.contains_key(&key));
```

## Security and data contracts

- Normal inventory fields do not require private/symmetric key bytes.
- Metadata validators reject recognized private-key PEM markers and oversized fields; collectors remain responsible for never submitting secrets. Pattern checking is not a guarantee against arbitrary secret leakage.
- Asset IDs use a versioned, type-specific canonical tuple. Ambiguous identities fail rather than merging across tenants or use sites.
- Source evidence and confidence are distinct from compliance, vulnerability severity, or migration readiness.
- Collector scope/coverage is explicit, including failed, unsupported, and partially inspected source items.
- No implicit host/network discovery occurs in the inventory model.
- Snapshot hashes bind source/provenance and schema semantics. Distinct collection runs can produce distinct snapshot digests even for the same underlying assets.

## Development and validation

The FOSS-2 story is tracked in [Linear](https://linear.app/lattix/issue/FOSS-2/implement-canonical-cryptographic-inventory-model) and [draft PR #3](https://github.com/LATTIX-IO/cryptomap/pull/3).

Required checks: `cargo fmt --all -- --check`, `cargo check --workspace --all-targets --all-features --locked`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --all-features --locked`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked`, dependency/deny/audit gates, and acceptance-fixture review.

The API remains pre-1.0 until all child issue acceptance criteria and CI checks pass. crates.io publishing is disabled.

## License

MIT OR Apache-2.0.
