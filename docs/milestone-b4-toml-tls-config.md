# Milestone B4 — explicitly scoped TOML TLS configuration evidence

Status: FOSS-372 development increment. This profile is opt-in, read-only, and never asserts negotiated TLS, algorithm execution, deployed configurations, compliance status, or an authenticated publisher. It is **not** a general TOML scanner. Cryptomap itself remains unpublishable (`publish = false`) pending the separate human release gate.

## Profile contract

Only a host-granted exact `.toml` file with the existing marker `cryptomap:tls-config:v1` and a real `[tls]` table is eligible:

```toml
profile = "cryptomap:tls-config:v1"

[tls]
versions = ["1.2", "1.3"]
cipher_suites = ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"]
```

The same reviewed whitelist and bounded serde sequence visitors as the B3 JSON profile apply. Supported TLS versions are `1.2` and `1.3`; suite values are restricted to `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, and `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`. These are **source strings**, not negotiated cipher support assertions.

The root must contain only `profile` and `[tls]`; the latter may contain only `versions` and `cipher_suites` arrays, both optional. Inline `tls = { ... }` is deliberately not supported. A syntactically valid empty table establishes `InspectedNoObservation`. A different, otherwise parseable versioned marker is `Unsupported`. Missing fields, duplicate keys or values, any extraneous/secret field, invalid types, invalid UTF-8, parsing errors or disallowed names are `Failed` with a typed nonrevealing diagnostic. A failed/unsupported source must never be treated as clean negative evidence.

The caller grants each exact file under `CollectionScope` and provides a trusted tenant, run, observation time and collector descriptor. Every authorization is verified before I/O, including in normalized and batch preflight. A collector bound to scope A cannot be run as scope B even if both have identical tenant/source labels. No automatic discovery, target execution, background processes, untrusted plugins, network probes, or recursive scanning occurs. Scope grants reject unsafe symlink traversal. **An in-process scope is not an OS sandbox.**

Each source is capped at 16 KiB; list limits are enforced while deserializing. Parsed fields are mapped to whitelisted configured-only `Protocol` and `Configuration` facts. Evidence includes actual source SHA-256 and digest-bound deterministic event identifiers. Source locators remain document-level; no artificial token spans are claimed. Content checksums are not signatures.

## Dependency and supply-chain boundary

The feature `toml-tls-config` activates the B3 `json-tls-config` profile semantic implementation and optional pinned `toml = 0.8.23` decoder with `default-features = false` and `parse` only. The maintained `toml-rs` parser provides real TOML duplicate-key validation; no ad-hoc hand-rolled TOML grammar or YAML/network interpreters are introduced. Default Cryptomap builds do not depend on this optional parser. The exact Cargo.lock must be reviewed and the direct dependency added to locked SPDX dependency checks. Parser/source semantics and frozen snapshot-v2 identity remain unchanged.

## Runnable exact-file example and acceptance gates

From workspace root:

```sh
cargo run --locked -p cryptomap --features toml-tls-config --example toml_scoped_tls -- \
  crates/cryptomap/examples/fixtures/config tls.toml 2026-10-13T15:00:00Z b4-tenant b4-run

cargo test -p cryptomap --test foss_372_toml_tls_config --features toml-tls-config --locked
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo package -p cryptomap --locked
bash scripts/verify-packaged-consumer.sh
```

Named Linux regressions cover exact profile, evidence/snapshot semantics, stable replay, scope mismatch (raw/isolated/normalized/batch), invalid/malformed/secret-bearing input, duplicate fields/values, byte/raw budgets, source mix, cancellation and symlink scope security. CI additionally requires Windows, Rust 1.85, package offline consumer, software SPDX and RustSec/deny/SemVer checks. **Merge only a fully reviewed exact-head green PR and then verify merged-main signed provenance**.

No part of this increment changes the crates.io publication state or claims a public registry release.
