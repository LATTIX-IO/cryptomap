# cryptomap

A Rust SDK for **evidence-backed cryptographic asset inventories** and conservative, source-authorized dependency collection. Maintained by Lattix Technologies Corp.

**Status:** pre-1.0 developer SDK candidate `0.1.1-alpha.1` (not yet published). The crates.io index already contains a separate `cryptomap 0.1.0` entry; its ownership must be verified before any publish. The current package remains `publish = false`. APIs and supported source profiles may change.

## Runnable collection from actual files

Cryptomap does not require developers to manually fabricate dependency inventory records. The reference example reads two explicitly authorized fixture files, normalizes their observations, proves direct dependencies against the lockfile, and verifies the resulting scope-bound snapshot:

```sh
cargo run --locked -p cryptomap --example cargo_scoped_inventory -- \
  crates/cryptomap/examples/fixtures/cargo 2026-10-12T12:00:00Z example-tenant example-run-1
```

For your own supported Cargo repository, substitute the **explicit directory containing both Cargo.toml and Cargo.lock** and provide an actual RFC3339 observation time, tenant/scope identifier and unique run prefix.

A parallel npm example is available, using only approved package.json and package-lock.json files:

```sh
cargo run --locked -p cryptomap --example npm_scoped_inventory -- \
  crates/cryptomap/examples/fixtures/npm 2026-10-12T12:00:00Z npm-example-tenant npm-example-run
```

Both file-backed examples are also compiled and run from the packaged crate in the offline clean-room consumer test. Never reuse demonstration identities across independent runs. Unsupported manifest semantics fail closed. No Cargo build, package download, script execution, recursive scan or network request is performed by the reference example.

The output is a verified snapshot digest plus asset, relationship and coverage counts; dependency presence **does not** establish that a cryptographic algorithm actually executes.

## Current capabilities and limitations

| Capability | Status |
|---|---|
| Typed assets, observations, evidence, confidence and provenance | Implemented |
| Scoped passive collector contract, normalization and coverage | Implemented |
| Deterministic immutable snapshots, import verification, queries and diffs | Implemented |
| Conservative Cargo.lock v3/v4 and exact-pinned Cargo.toml | Implemented, deliberately limited syntax |
| Conservative npm package.json + package-lock v2/v3 | Implemented, deliberately limited syntax |
| Optional Rust qualified source-call collector | B2 developer preview; `rust-source` feature, exact-file AST evidence only |
| Optional JSON TLS configuration profile collector | B3 developer preview; `json-tls-config` feature, configured-only claims |
| Public X.509 / live TLS / general source-call / telemetry collectors | Planned; **not shipped** |
| CycloneDX CBOM 1.7 import/export | Planned; **not shipped** |
| Cryptopolicy / cryptoshift interoperability adapters | Planned; **not shipped** |
| Standalone CLI, recursive repository crypto scan, algorithm execution proof | **Not claimed** |

The library distinguishes configured/present/observed cryptography, separates evidence confidence from compliance scores, does not extract private key bytes by default, and does not authorize untrusted collector process execution.

## Documentation and development

- [Milestone A user journey, security bounds and release procedure](docs/milestone-a-release-readiness.md)
- [Windows hands-on Milestone A verification: inspect collectors, negative cases, archive and attestations](docs/milestone-a-windows-manual-validation.md)
- [Milestone B2 optional Rust source-evidence collector, boundaries and quickstart](docs/milestone-b2-rust-source-evidence.md)
- [Milestone B3 opt-in JSON TLS configuration evidence and security boundaries](docs/milestone-b3-json-tls-config.md)
- [Milestone B4 opt-in TOML TLS configuration evidence and security boundaries](docs/milestone-b4-toml-tls-config.md)
- [Milestone B5.1 opt-in public X.509 certificate file evidence](docs/milestone-b5-certificate-files.md)
- [Software SBOM and main-only attestation trust boundary](docs/milestone-a-sbom-attestations.md)
- [Crate developer guide](crates/cryptomap/README.md)
- [Collector author sample](crates/cryptomap/examples/collector_skeleton.rs)
- [Collector author guide and clean-room consumer](docs/collector-author-guide.md)
- [Milestone B1 opt-in source fault isolation and diagnostics](docs/milestone-b1-isolated-diagnostics.md)
- [Versioned compatibility and schema policy](docs/compatibility-policy.md)
- [Milestone A supported-input matrix and frozen identity vectors](docs/milestone-a-sdk-compatibility.md)
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
