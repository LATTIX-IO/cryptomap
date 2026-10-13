# Milestone A SDK compatibility and acceptance contract

## Release profile

Rust 1.85+, Edition 2024. This first developer preview provides a **passive, embedding-only evidence inventory SDK**, not an automatic crypto scanner, compliance tool, CBOM exporter, vulnerability analyzer, or proof of algorithm execution. The public API supplies types, observed evidence, source-scoped collectors, normalization, immutable verified snapshots, queries and diffs.

### Supported source acceptance

| Source profile | Mode | Input capability | Output and limits |
| --- | --- | --- | --- |
| Cargo.toml exact pins + Cargo.lock v3/v4 | Passive | Explicitly grant two named local files | Source evidence, verified direct dependencies; no target/workspace/dev/optional/range resolution |
| npm package.json exact pins + package-lock v2/v3 | Passive | Explicitly grant two named local files | Source-bound installed/direct evidence; no script execution, peer/dev/workspace/alias/range coverage |
| Custom `Collector` implementation | Host supplied | Declare accurate sources/modes and independent grants | Trusted in-process extension, **not** sandboxed arbitrary code |
| TLS/X.509/source-call/runtime telemetry | Not available | None | No claims or automatic detection |
| CycloneDX CBOM import/export | Not available | None | No CBOM claims |
| Cryptopolicy/Cryptoshift integration | Not available | None | No policy/migration decisions |

Cargo and npm developer examples can be run from the repository root and **from a fresh external consumer of the actual packaged .crate**. They accept a host-supplied RFC3339 observation timestamp, a trusted tenant/scope and unique per-collection run prefix. They do not infer a scope from user-controlled package metadata.

```sh
cargo run --locked -p cryptomap --example cargo_scoped_inventory -- crates/cryptomap/examples/fixtures/cargo 2026-10-12T12:00:00Z sample-tenant cargo-run
cargo run --locked -p cryptomap --example npm_scoped_inventory -- crates/cryptomap/examples/fixtures/npm 2026-10-12T12:00:00Z sample-tenant npm-run
```

## Explicit semantic protections

- Library present != algorithm used. Configured support != observed negotiation. A failed or unsupported collection != cryptography absent.
- Evidence confidence != risk, severity or compliance.
- Mixed tenant scopes and rehashed foreign-tampered snapshots must be rejected on verified import.
- Versioned `asset:v2` IDs distinguish logical identity and tenant; canonical normalization (e.g. Cargo ecosystem case) must not cause accidental drift.
- An inventory digest is integrity/self-consistency, not a producer signature or external authentication. Source SHA-256 records source bytes and does not prove who supplied them.

## Frozen positive vectors

`crates/cryptomap/tests/milestone_a_identity_golden.rs` protects the SHA-256 canonical identifier byte contract:

- Cargo library Ring 0.17.12 under tenant-a.
- TCP endpoint at EXAMPLE.com.:443 / prod under tenant-a.
- Same Cargo library under tenant-b (must differ).
- Case-normalization aliases of cargo/Ring must produce identical AssetId.

The golden values were derived from the documented identity domain separator, canonical JSON tuple and `asset:v2` shape. They are normative for this preview: a change requires intentional identity/schema versioning, migration notes and review, never an automatic fixture update merely to pass CI.

## Frozen snapshot-v2 and ChangeSet contracts

`crates/cryptomap/tests/milestone_a_snapshot_diff_golden.rs` fixes three normative SHA-256 snapshot IDs for schema 2, computed from a precisely described, run-less *legacy compatibility* fixture with explicit Cargo library assets and two source-coverage entries. These are **not** independently authorized tenant snapshots; verified import under a trusted scope must reject them. The test intentionally separates integrity from authentication.

The vectors pin BTreeMap order independence, exact canonical content encoding, verified JSON round trips, and rejection of hash/metadata tampering and unsupported future schema versions. Full reinspection of every previously covered source confirms an asset removal; missing coverage keeps the same absence **tentative**. The CI checks exact added/removed/tentative/unchanged sets and coverage-changed identifiers.

Any changed SHA-256 fixture must be reviewed with the canonical tuple/schema implementation and explicit migration rationale; never auto-refresh normative hashes to accommodate a regression. These vectors are a high-risk release gate, not proof that all future CBOM extensions are compatible.

## Release and future compatibility

The SDK is pre-1.0 and may evolve. Run stable and MSRV Windows/Linux CI, strict Clippy, tests, rustdoc, package/clean-room consumption, and identity golden tests before merge. The package cannot be published until a separate human-authorized release PR, crates.io ownership verification, approved version/changelog and a registry dry-run pass. SBOM/software provenance does not substitute for Cryptomap's future CycloneDX CBOM support.
