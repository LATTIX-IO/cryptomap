# Writing a Cryptomap collector — public Rust SDK guide

## Trust model

The `Collector` trait is an extension boundary, **not** an OS sandbox. A host must approve every file/endpoint/source, use `CollectionScope` and `collect_scoped` for authorized collections, and isolate any untrusted plugin at the OS/process level. A declared `required_permissions` value does not itself confer authority. No implicit path crawling or network probes are permitted.

A collector has three separable responsibilities:

1. **Declare** a versioned ID, passive/active mode, supported `RawSourceKind`, permission requirements and checkpoint capability through `CollectorDescriptor`.
2. **Emit** bounded `RawObservation` records through `CollectionSink`, maintaining immutable event identity, source item, collection run, observation timestamp, direct/inferred evidence confidence and nonsecret metadata.
3. **Report coverage** of each requested source, including inspected-observed, inspected-no-observation, unsupported, partial and failed cases. A failed/partial source cannot be misreported as a proven absence.

## Runnable third-party example

The source file `crates/cryptomap/examples/collector_skeleton.rs` implements a fixture-only passive collector. From the workspace root:

```sh
cargo run --locked -p cryptomap --example collector_skeleton
```

The sample creates a synthetic dependency observation, not a real filesystem scan or cryptographic execution claim. It is appropriate to learn the collector trait before implementing a granted file collector.

CI tests **external adoption** using the actual packaged `.crate`:
- `cargo package --package cryptomap --locked` builds the distributable archive.
- `scripts/verify-packaged-consumer.sh` unpacks the artifact, vendors the reviewed dependency lock into a fresh temporary Cargo home, builds an independent consumer and copies the packaged collector sample as a binary into that external consumer.
- Both custom collector and source-granted Cargo manifest/lock examples run offline under `--locked`. This is stronger than merely compiling an example inside the workspace.

## From synthetic observation to real data

For an authorized `Cargo.toml`, `Cargo.lock`, npm manifest or supported lockfile, first have a trusted caller grant the explicit files with `CollectionScope::grant_file` and hard input byte ceilings. Read only through `scope.open_file`; use the built-in collectors when their strict grammar accepts the supplied source. Never call Cargo/npm install, run package scripts or follow arbitrary external symlinks.

Build the authorized `CollectionRequest` with unique host-generated run ID, exact requested source list and `RawLimits`. Invoke `collect_scoped`, then the existing normalization/batch pipeline under independently trusted `IdentityContext`, `CollectionScopeId` and `InventoryLimits`. Only add direct dependencies after a manifest/lock source-bound proof. Verify the resulting snapshot against the independently authorized scope.

The [reference example](../crates/cryptomap/examples/cargo_scoped_inventory.rs) demonstrates these stages using real bytes. It requires a caller-chosen scope and per-collection run prefix to avoid accidentally merging unrelated provenance.

## Conformance and failure modes

Before contributing a collector, test the following externally, not only as internal unit tests: unauthorized source denial; symlink/path escape rejection; repeated/colliding event IDs; malformed or over-budget inputs; malformed/unknown algorithm identifiers; explicit no-observation versus not-inspected coverage; cancellation and time budgets; deterministic replay; tenant mismatch; source digest mutation; and prevention of accidental private-key collection or credential echoing.

Unsupported grammar must produce a typed diagnostic and incomplete coverage, never successful empty inventory. A returned source hash does not authenticate the collector or establish algorithm execution.

The current crate does not ship ready-made certificate, TLS, source/configuration, runtime telemetry or CBOM adapters. Do not use future API examples in production until those features are implemented and conformance-tested.
