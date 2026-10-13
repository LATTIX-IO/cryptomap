# Milestone A — deterministic Cargo/npm robustness smoke

## Boundary and objective

Milestone A ships conservative read-only exact-file Cargo and npm collectors. These collectors must reject malformed and unsupported inputs without promoting an incomplete inspection to an empty/clean cryptographic inventory. This test is a **bounded deterministic corpus-based fuzz smoke**, not a continuous coverage-guided fuzz campaign or a proof of memory safety for arbitrary inputs.

## Entrypoint and reproducibility

Run from repository root:

    cargo test -p cryptomap --test milestone_a_collector_robustness --locked

CI runs this by name after all workspace tests. Rust stable, Windows and the Rust 1.85 job run the same test as part of the complete test matrix. No network, package manager subprocess, external fuzz service, nightly Rust or untrusted plugin execution is required.

## Threat model

Each generated source is written into an isolated temporary directory and explicitly granted as exactly one local file under a tenant-scoped CollectionScope with a fixed 4,096-byte budget.

The test exercises all three passive collector entry points (Cargo.toml, npm package.json and npm package-lock.json). For 32 deterministic cases per format, it inserts unsupported manifest keys or escape-path lock entries. For another 32 cases per format, it creates invalid UTF-8 with a fixed-seed varying byte tail.

All known-invalid inputs must produce a Failed collection, failed coverage, zero observations and at least one diagnostic. This explicitly prevents a failed parse from being mistaken for inspected-no-observation or cryptography absent.

The tests do not inspect private keys, execute Cargo/npm, recursively traverse repositories or access a network. Fixed source bytes and seed make failures reproducible.

## Bounded snapshot finalization and diff benchmark smoke

The same increment adds `crates/cryptomap/tests/milestone_a_inventory_scale_smoke.rs`. It inserts 1,024 already-canonical library assets in both insertion orders, compares exact snapshot finalization and hashes, verifies the serialized JSON import, requires a 1,023-asset limit to reject the larger snapshot, and checks the exact 512-asset addition set when diffing against a half-size inventory. This **does not benchmark public collector normalization**, which is covered functionally by the existing pipeline and clean-room integration tests. CI emits one elapsed-time and serialized-size line under `--nocapture` to enable regression investigation.

This is an **observational benchmark smoke**, not a universal CPU/memory throughput SLO. No wall-clock threshold is used on nondeterministic shared runners. It uses a fixed, capped workload and no external dependencies.

## Definition of done

1. All deterministic cases fail closed through the **public collector orchestration API**, not a private parser-only helper.
2. No false inspected coverage or partially published observations escape the rejection path.
3. No panics, timeouts or platform-dependent behavior in the bounded corpus or 1,024-asset snapshot-finalization/diff benchmark smoke on Rust 1.85, Linux and Windows.
4. Every exact-head CI quality/security/packaging and offline-consumer gate remains green, including CodeRabbit/Codex independent review findings.
5. Do not claim full fuzz campaign coverage, arbitrary TOML/npm semantic support or real-world algorithm-use detection. More comprehensive fuzzing and benchmark performance SLOs remain future research work.

This closes a *Milestone A alpha release smoke requirement only*; it does not change source-input grammar, collector contracts or `publish = false`.
