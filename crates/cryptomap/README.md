# cryptomap — Rust inventory SDK (pre-1.0)

Cryptomap records *observations and supporting evidence* of cryptographic assets. It is not a compliance or PQC migration engine, and a package's presence does not imply actual execution of its algorithms.

## Minimal public API

```rust
use cryptomap::{AssetKind, IdentityContext, InventoryBuilder, InventoryLimits};
use std::collections::BTreeMap;

let context = IdentityContext::new("example").unwrap();
let mut builder = InventoryBuilder::new();
let id = builder.ingest_candidate(
    AssetKind::Library {
        ecosystem: "cargo".into(),
        name: "ring".into(),
        version: "0.17.12".into(),
    },
    &context,
    BTreeMap::new(),
).unwrap();
let snapshot = builder.finalize(InventoryLimits::default()).unwrap();
snapshot.verify(InventoryLimits::default()).unwrap();
assert!(snapshot.assets.contains_key(&id));
```

The snippet above demonstrates the canonical model. For **actual file collection**, use the [Cargo reference example](examples/cargo_scoped_inventory.rs); it grants two exact authorized files, invokes Cargo manifest and lock collectors, normalizes their source evidence, adds proven direct dependency edges, and independently verifies the snapshot.

From the repository root:

```sh
cargo run --locked -p cryptomap --example cargo_scoped_inventory -- \
  crates/cryptomap/examples/fixtures/cargo 2026-10-12T12:00:00Z
```

The timestamp is supplied by the host and must describe the actual observation window for nonfixture collection. This is an *explicit directory* tool, not recursive scanning. Unsupported Cargo grammar is rejected instead of implying no cryptographic dependencies.

## Concepts

- **Asset** — a canonical logical identity; duplicate asset names are not enough to equate separate use sites.
- **Observation** — an immutable assertion about an asset, linked to source **Evidence** (collector/run/time, source locator, confidence and direct/inferred classification).
- **Coverage** — records inspected, failed, unsupported, partial and uninspected input. Absence after partial collection is not evidence of removal.
- **InventorySnapshot** — deterministic, digest-bound, immutable inventory state. Verify an imported snapshot with the caller-trusted scope before using it.
- **ChangeSet** — typed change and tentative-removal semantics, not policy/risk conclusions.

## Supported source profiles

The passive Cargo subset supports lockfile v3/v4 and bounded, exact numeric direct dependency declarations; it accepts only specifically supported metadata and version-only inline-table syntax. Npm supports package-lock v2/v3 with strict exact-root and installation profiles. Unsupported version ranges, Cargo workspace/target/dev/optional/renamed declarations, and npm peer/dev/workspace/alias semantics are not silently interpreted.

Other collectors (X.509, TLS, source/config, telemetry), the CycloneDX CBOM adapter, and cryptopolicy/cryptoshift bridges are **not yet available**.

## Security and contributor notes

Never run an untrusted collector in-process as if a scope grant were an OS sandbox. Verify all source grants, cap byte budgets, avoid logging unredacted snapshots and credential-bearing metadata, and do not equate source hashes with signatures. The [collector skeleton](examples/collector_skeleton.rs) illustrates the third-party collector interface without real I/O.

See the [release readiness and consumer guide](../../docs/milestone-a-release-readiness.md) for commands, CI expectations, limitations and release safeguards.

The package remains `publish = false` until an explicitly approved first alpha publication. SPDX license expression: MIT OR Apache-2.0.
