# cryptomap

A Rust SDK for **evidence-backed cryptographic asset inventories** and conservative, source-authorized dependency collection. Maintained by Lattix Technologies Corp.

**Status:** pre-1.0 developer preview; not yet published to crates.io. The package is deliberately marked `publish = false`. APIs and supported source profiles remain subject to change.

## Runnable collection from actual files

Cryptomap does not require developers to manually fabricate dependency inventory records. The reference example reads two explicitly authorized fixture files, normalizes their observations, proves direct dependencies against the lockfile, and verifies the resulting scope-bound snapshot:

```sh
cargo run --locked -p cryptomap --example cargo_scoped_inventory -- \
  crates/cryptomap/examples/fixtures/cargo 2026-10-12T12:00:00Z example-tenant example-run-1
```

For your own supported Cargo repository, substitute the **explicit directory containing both Cargo.toml and Cargo.lock** and provide the actual observation time in RFC3339, a tenant/scope identifier and a unique run prefix. Never reuse demonstration identities across independent runs. Unsupported manifest semantics fail closed. No Cargo build, package download, script execution, recursive scan or network request is performed by the reference example.

The output is a verified snapshot digest plus asset, relationship and coverage counts; dependency presence **does not** establish that a cryptographic algorithm actually executes.

## Current capabilities and limitations

| Capability | Status |
|---|---|
| Typed assets, observations, evidence, confidence and provenance | Implemented |
| Scoped passive collector contract, normalization and coverage | Implemented |
| Deterministic immutable snapshots, import verification, queries and diffs | Implemented |
| Conservative Cargo.lock v3/v4 and exact-pinned Cargo.toml | Implemented, deliberately limited syntax |
| Conservative npm package.json + package-lock v2/v3 | Implemented, deliberately limited syntax |
| Public X.509 / live TLS / source-call / telemetry collectors | Planned; **not shipped** |
| CycloneDX CBOM 1.7 import/export | Planned; **not shipped** |
| Cryptopolicy / cryptoshift interoperability adapters | Planned; **not shipped** |
| Standalone CLI, recursive repository crypto scan, algorithm execution proof | **Not claimed** |

The library distinguishes configured/present/observed cryptography, separates evidence confidence from compliance scores, does not extract private key bytes by default, and does not authorize untrusted collector process execution.

## Documentation and development

- [Milestone A user journey, security bounds and release procedure](docs/milestone-a-release-readiness.md)
- [Crate developer guide](crates/cryptomap/README.md)
- [Collector author sample](crates/cryptomap/examples/collector_skeleton.rs)
- [Contribution policy](CONTRIBUTING.md)
- [Security disclosure](SECURITY.md)

Validation from the workspace root:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo package --package cryptomap --locked
bash scripts/verify-packaged-consumer.sh
```

Linux CI additionally checks rustdoc, dependency advisories, licenses, SemVer and the packaged clean-room consumer; Windows and Rust 1.85 are independently tested.

## Publishing

Publication is intentionally blocked in the crate manifest. The release-plz publishing job additionally requires a manual `workflow_dispatch` on `main` and an explicit `CRYPTOMAP_RELEASE_ENABLED=true` repository variable. Ordinary pushes cannot publish, even when the opt-in variable is enabled. Review `docs/milestone-a-release-readiness.md` before any publishing PR. No published crates.io or GitHub release is claimed.

## License

MIT OR Apache-2.0.
