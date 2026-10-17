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

The snippet above demonstrates the canonical model. For **actual file collection**, use the [Cargo reference example](examples/cargo_scoped_inventory.rs) or the [npm reference example](examples/npm_scoped_inventory.rs). Each grants exactly two independently authorized input files, invokes the relevant passive manifest/lock collectors, normalizes the original source evidence, proves direct dependency edges and independently verifies the resulting scope-bound snapshot.

```sh
cargo run --locked -p cryptomap --example npm_scoped_inventory -- \
  crates/cryptomap/examples/fixtures/npm 2026-10-12T12:00:00Z npm-tenant npm-run-1
```

The examples do not recursively discover repositories or prove runtime cryptographic algorithm use.

From the repository root:

```sh
cargo run --locked -p cryptomap --example cargo_scoped_inventory -- \
  crates/cryptomap/examples/fixtures/cargo 2026-10-12T12:00:00Z example-tenant example-run-1
```

The timestamp, tenant/scope identifier and distinct run prefix are supplied by the host. A new run prefix is required for every independent collection; fixed example values are only for reproducible fixtures. This is an *explicit directory* tool, not recursive scanning. Unsupported Cargo grammar is rejected instead of implying no cryptographic dependencies.

## Optional isolated collector mode (Milestone B1, unreleased)

For trusted, independently invocable collectors, `collect_scoped_isolated` retains successful sources when another source returns an ordinary collection error, while rejecting forged events and cross-source collisions. Use `CollectionSummary::from_outcome` for payload-free counters and `collect_normalized_isolated` for immediately validated snapshots. This is not an OS sandbox and is not yet an automatic source scanner; strict collection remains the default. See [B1 contract and tests](../../docs/milestone-b1-isolated-diagnostics.md).

## Optional Rust source syntax evidence (Milestone B2 developer preview)

The feature-gated `rust-source` collector parses only explicitly authorized Rust `.rs` files to report a small whitelist of *syntactic* qualified calls. It emits source-verified `SourceUse` evidence with call-site location, rather than asserting algorithm execution or guessing a dependency graph.

```sh
cargo run --locked -p cryptomap --features rust-source --example rust_scoped_source -- \
  crates/cryptomap/examples/fixtures/source crypto_calls.rs \
  2026-10-13T15:00:00Z example-tenant example-rust-run
```

The parser feature is disabled by default. See [Milestone B2 documentation](../../docs/milestone-b2-rust-source-evidence.md) for the exact syntactic whitelist, security limits and regression tests.

## Optional JSON TLS configuration evidence (Milestone B3 developer preview)

The off-by-default `json-tls-config` collector reads one explicitly granted JSON configuration file with the exact `cryptomap:tls-config:v1` marker and emits configured protocol versions and named cipher-suite claims. It neither connects to TLS endpoints nor establishes negotiation or executable algorithm use.

```sh
cargo run --locked -p cryptomap --features json-tls-config --example json_scoped_tls -- \
  crates/cryptomap/examples/fixtures/config tls.json \
  2026-10-13T15:00:00Z example-json-tenant example-json-run
```

See the [profile schema, security limitations and failure semantics](../../docs/milestone-b3-json-tls-config.md).

## Optional public X.509 certificate-file evidence (Milestone B5.1 preview)

The default-off `certificate-files` collector parses only host-granted public PEM/DER certificate files. It emits DER SHA-256 fingerprints, bounded public algorithm OIDs, exact source digests and inspection coverage. It does **not** assert trust, private-key possession, hostname validation, revocation or negotiated TLS use.

```sh
cargo run --locked -p cryptomap --features certificate-files --example certificate_scoped_inventory -- \
  crates/cryptomap/examples/fixtures/certificate rsa.pem \
  2026-10-16T12:00:00Z example-certificate-tenant example-certificate-run
```

See [B5.1 certificate-file input limits and security tests](../../docs/milestone-b5-certificate-files.md).

## Optional typed certificate-store grants (Milestone B5.2 preview)

The default-off `certificate-store-grants` feature permits a trusted host to construct an exact, finite, non-executing `CurrentUser/My` or separately authorized `LocalMachine/My` certificate-store grant. Its `RawSourceKind::CertificateStore` is distinct from the file-grant `RawSourceKind::Certificate`. This feature contains **no native store enumerator** and does not read any keys or certificates. All requests must pass the standard scope-bound preflight, and missing grants fail closed.

```sh
cargo run --locked -p cryptomap --features certificate-store-grants --example certificate_store_authorization
cargo test --locked -p cryptomap --features certificate-store-grants --test foss_467_certificate_store_grants
```

See [B5.2 typed grant authority, budgets and failure semantics](../../docs/milestone-b5-certificate-store-grants.md). Actual read-only Windows store collection is planned in FOSS-468, not claimed in B5.2.

## Opt-in read-only Windows certificate-store adapter (B5.3 draft)

The separate `cryptomap-windows-store` workspace crate connects the exact B5.2 typed store-grant contract to the Windows CryptoAPI **read-only local registry** store for CurrentUser/My or separately approved LocalMachine/My. It supplies public DER certificates to the same canonical B5.1 decoder and emits typed coverage; no keys, subjects, issuer names, serials, or raw DER are included in normal reports. It remains in [draft PR #67](https://github.com/LATTIX-IO/cryptomap/pull/67), not a published artifact or completed release.

The Linux/macOS provider reports `Unsupported` and does not pretend a store was inspected. The Windows CI suite uses only ephemeral **in-memory** stores. See [B5.3 trust boundaries, tests, and optional manual read-only UAT](../../docs/milestone-b5-windows-store.md).

## Concepts

- **Asset** — a canonical logical identity; duplicate asset names are not enough to equate separate use sites.
- **Observation** — an immutable assertion about an asset, linked to source **Evidence** (collector/run/time, source locator, confidence and direct/inferred classification).
- **Coverage** — records inspected, failed, unsupported, partial and uninspected input. Absence after partial collection is not evidence of removal.
- **InventorySnapshot** — deterministic, digest-bound, immutable inventory state. Verify an imported snapshot with the caller-trusted scope before using it.
- **ChangeSet** — typed change and tentative-removal semantics, not policy/risk conclusions.

## Supported source profiles

The passive Cargo subset supports lockfile v3/v4 and bounded, exact numeric direct dependency declarations; it accepts only specifically supported metadata and version-only inline-table syntax. Npm supports package-lock v2/v3 with strict exact-root and installation profiles. Unsupported version ranges, Cargo workspace/target/dev/optional/renamed declarations, and npm peer/dev/workspace/alias semantics are not silently interpreted.

Windows read-only certificate-store enumeration is under development in B5.3, not merged or published. Live negotiated TLS, general multi-language source/config discovery, runtime telemetry, the CycloneDX CBOM adapter and cryptopolicy/cryptoshift bridges are **not yet available**. Public X.509 **file** evidence and inert named-store **authorization** are limited opt-in previews, not an automatic certificate discovery service.

## Security and contributor notes

Never run an untrusted collector in-process as if a scope grant were an OS sandbox. Verify all source grants, cap byte budgets, avoid logging unredacted snapshots and credential-bearing metadata, and do not equate source hashes with signatures. The [collector skeleton](examples/collector_skeleton.rs) illustrates the third-party collector interface without real I/O.

See the [collector author guide](../../docs/collector-author-guide.md), [compatibility policy](../../docs/compatibility-policy.md), [Milestone A frozen identity vectors](../../docs/milestone-a-sdk-compatibility.md), and [release readiness and consumer guide](../../docs/milestone-a-release-readiness.md) for commands, CI expectations, limitations and release safeguards.

The package remains `publish = false` until an explicitly approved first alpha publication. The publishing workflow also requires a manual dispatch and repository opt-in. SPDX license expression: MIT OR Apache-2.0.
