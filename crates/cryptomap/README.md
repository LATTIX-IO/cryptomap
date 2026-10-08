# cryptomap

Evidence-backed cryptographic inventory types, observations, deterministic snapshots, and snapshot comparisons.

## Scope

The public model distinguishes an `Asset` (canonical logical entity) from an `Observation` (one evidence-backed claim), `Evidence` (collector/source provenance), and an `InventorySnapshot` (finalized immutable inventory). The crate intentionally does not make compliance decisions, scan arbitrary hosts, or store private-key material.

## Example

```rust
use cryptomap::{Asset, AssetId, AssetKind, InventoryBuilder, InventoryLimits};
use std::collections::BTreeMap;

let mut inventory = InventoryBuilder::new();
inventory.add_asset(Asset {
    id: AssetId::new("package:cargo/openssl@1").unwrap(),
    kind: AssetKind::Library {
        ecosystem: "cargo".into(),
        name: "openssl".into(),
        version: "1".into(),
    },
    extensions: BTreeMap::new(),
}).unwrap();

let snapshot = inventory.finalize(InventoryLimits::default()).unwrap();
assert_eq!(snapshot.assets.len(), 1);
```

## Current status

FOSS-2 / FOSS-3 implementation is in progress. This first slice establishes typed asset/observation/evidence/relationship identities, deterministic map ordering and snapshot digests, cross-reference validation, conflict preservation, coverage, asset-level diff, and query primitives.

Remaining before story acceptance: canonical identity derivation across collectors, comprehensive asset and relationship variants, observation/evidence-aware diff classification, explicit confidence-change detection, snapshot deserialization verification, property/fuzz tests, provenance-rich fixture corpus, and release packaging. The Rust dependency lockfile must be regenerated and tests run.

## License

MIT OR Apache-2.0.
