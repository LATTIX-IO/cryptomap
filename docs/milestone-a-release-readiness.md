# Milestone A — cryptomap v0.1 developer preview

## Scope and product promise

A passive, evidence-backed **Rust inventory SDK**. The supported feature slice includes typed assets, observations, explicit collector scope and coverage, immutable SHA-256-bound snapshots, query and diff APIs, and conservative Cargo/npm dependency inventory. Dependency presence proves a package exists in approved evidence; it does **not** prove an algorithm was called. Neither source code execution nor network/package-manager access is performed by the supplied passive collectors.

This release is **not** full repository cryptographic-use discovery, vulnerability/compliance evaluation, post-quantum migration planning, or CycloneDX CBOM import/export. Certificate, TLS, source-code and telemetry collectors, CBOM adapters, and cryptopolicy/cryptoshift projections are planned separately.

## Reproducible user journey

From the repository root, using Rust 1.85 or later:

```shell
cargo run --locked -p cryptomap --example cargo_scoped_inventory -- crates/cryptomap/examples/fixtures/cargo 2026-10-12T12:00:00Z example-tenant example-run-1
```

Alternatively, run inside the crate directory:

```shell
cd crates/cryptomap
cargo run --locked --example cargo_scoped_inventory -- examples/fixtures/cargo 2026-10-12T12:00:00Z example-tenant example-run-1
```

Both commands invoke the same example. The UTC timestamp is illustrative fixture metadata; integrations must supply an accurate, independently obtained RFC3339 observation time and an **independently authorized tenant/scope identity and unique per-collection run prefix**. Example identifiers are not safe to reuse in production.

The repository fixture uses literal `Cargo.toml` and `Cargo.lock` filenames. Cargo deliberately excludes nested Cargo projects when constructing library archives. The packaged release therefore embeds the same sample bytes as `examples/fixtures/manifest.fixture` and `examples/fixtures/lock.fixture`; the offline consumer smoke test copies them into caller-owned temporary `Cargo.toml` and `Cargo.lock` files before invoking the packaged example. This avoids relying on workspace source paths after packaging.

The reference example:
1. Grants exactly the chosen directory's `Cargo.toml` and `Cargo.lock` through two independent file capabilities with a 1 MiB per-file ceiling.
2. Runs read-only Cargo manifest/lock collectors under explicit run identifiers.
3. Normalizes both outcomes into one scope-bound canonical inventory.
4. Re-reads and verifies source-bound exact direct dependency claims before adding `DependsOn` relationships.
5. Verifies the resulting canonical snapshot against the original trusted tenant/scope and prints bounded summary counts.

Input limitations are material. Cargo 3/4 lock formats and a strictly bounded exact-pin subset of Cargo.toml are supported, including validated package `edition`, `rust-version`, `publish` and version-only inline exact-pin declarations. Workspace, path/Git, optional, dev/build/target/renamed profiles, semantic version ranges and ambiguous evidence currently fail closed. Npm v2/v3 root and exact-pin profiles are separately implemented; full npm installation semantics are not represented.

For a real repository with unsupported profiles, a failed command **does not mean no cryptography was found**. It means that this profile could not establish a sufficiently bounded, authorized dependency proof.

## Security and privacy boundaries

- The host grants exact files; no recursive discovery, hidden globbing, Cargo invocation, installation scripts or outbound networking occurs.
- Scope is an in-process capability contract for trusted collector code, *not* a sandbox for untrusted plugins.
- Source URLs and paths may contain sensitive material. The demonstration prints only snapshot IDs and aggregate counts. Do not publish unredacted raw inventory snapshots without a separate privacy review.
- Imported snapshots require independent scope authorization; hashes detect changes but are not signatures or provenance authentication.
- Collection confidence, partial/unsupported status and direct/inferred evidence are not compliance findings or cryptographic-use assertions.

## Quality gates — executable

```shell
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo package --package cryptomap --locked
bash scripts/verify-packaged-consumer.sh
```

The clean-room script extracts the actual `.crate`, builds a new unrelated consumer package against that extracted artifact using an isolated Cargo home and vendored sources pinned by the reviewed workspace lockfile, then runs it offline with a generated, locked consumer graph, then compiles and executes the packaged end-to-end example. CI also runs dependency audit, deny policy, SemVer compatibility, Windows and Rust 1.85.

## Release/approval procedure — deliberately still closed

1. Confirm full CI, security review and the package-consumer gate at the exact candidate SHA. Review public API, supported profiles and source privacy against the actual packaged contents.
2. Check availability/ownership of the exact `cryptomap` crate name immediately before publishing. It is **not** verified by CI.
3. Update CHANGELOG and version; record SemVer/schema/collector compatibility, irreversible crates.io package digest, Git commit and release notes.
4. Obtain deliberate release authorization and check crates.io token/trusted publishing configuration. Release-plz publishing additionally requires a manual `workflow_dispatch` on `main` and repository variable `CRYPTOMAP_RELEASE_ENABLED=true`; ordinary merges cannot publish. The crate itself remains `publish = false`.
5. In a separate, reviewed release PR, change only the intentional publication settings and release metadata, validate `cargo publish --dry-run -p cryptomap --locked`, then confirm publishing manually through a protected workflow.
6. After publication, test installation of the **registry-distributed** version in a fresh project, verify docs.rs/GitHub release/SBOM/provenance and revoke/rotate credentials when applicable. The current clean-room gate tests a locally produced archive, *not* the crates.io registry.

Never enable publication as part of a feature-development merge. Existing release-plz token/configuration and GitHub permissions must be checked by a human with appropriate repository administration access before release.

## Remaining work for Milestone A closure

- Document the intended public API stability and compatibility/change policy (FOSS-17/18).
- Additional clean-room custom-collector and npm consumer examples; review supported versions and real-world fixtures.
- Release SBOM, artifact provenance, compatibility-golden baseline, safety/fuzz smoke, and protected publishing (FOSS-19/20).
- Registry name/owner and permissions confirmation followed by a deliberately approved alpha publish.
