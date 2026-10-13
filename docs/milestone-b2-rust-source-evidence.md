# Milestone B2: passive Rust cryptographic API call-site evidence

**Status:** development increment FOSS-370, not a general Rust cryptography scanner or crates.io publishing authorization. `rust-source` is off by default and opts into an AST/parser dependency without changing the Milestone A snapshot-v2 encoding or public Collector wire contract.

## Exact scope and trust model

A trusted host grants each explicitly chosen `.rs` file using `CollectionScope::grant_file(RawSourceKind::Source, item, root, relative, max_bytes)`. The collector never searches a repository, expands globs, enumerates directories, executes Cargo or project code, loads macros, resolves imports, connects to a network or retrieves secrets. It reopens each granted source through the rooted capability, rejects symlink/junction indirection, reads no more than 32 KiB per source and enforces an intentionally conservative 64-total-opening-delimiter-byte ceiling before tokenization (counting even delimiters in comments and strings to prevent hidden real nesting), bounded structural depth and total token count, and a 128-token cumulative syntactic-chain budget that carries parent expression depth into nested token groups, resets only the local segment at statement semicolons, and never resets at commas before recursive AST parsing. Long expression chains, comma-separated recursive generic types, nested brace/unary chains, and quoted-delimiter nesting tricks fail as `ResourceLimit` even if small in bytes. Some otherwise valid Rust files with many delimiters will be marked `Failed` rather than falsely treated as clean; a future streaming lexical preflight can improve coverage without weakening this safety bound.

The same file must have `.rs` as its actual granted relative extension; a request label alone cannot cause another file type to be parsed. Unsupported file types remain `Unsupported`, malformed or invalid-UTF8 files remain `Failed`, and exceeded byte/token/nesting budgets remain `Failed` with `ResourceLimit`. They are **never** `InspectedNoObservation`. A successfully inspected supported file with no reviewed calls legitimately has that no-observation coverage.

The built-in Rust source collector binds its file grants to the exact host scope instance via the optional `Collector::bound_scope` hook. Both raw scoped invocation and host-pinned canonical or batch preflight reject different scope objects, **even when their scope IDs and requested item names match**. Third-party in-process collectors that retain a scope must provide this binding themselves; an untrusted plugin still requires OS isolation.

The source extension must be enabled explicitly. For untrusted third-party collectors, `CollectionScope` is **not a process sandbox**; isolate foreign code at the OS boundary. Source digests provide content integrity correlation, not producer authentication. Normalize via a host-pinned `PipelineInput`, then verify the snapshot against the independently trusted scope.

## What the parser currently detects

| Exact syntactic call path | Stored source assertion | Caveat |
| --- | --- | --- |
| `sha2::Sha256::digest(...)` | `source:qualified-crypto-api-call` = `sha2::Sha256::digest` | Does not prove the method resolved to the sha2 crate or executed |
| `sha2::Sha512::digest(...)` | `source:qualified-crypto-api-call` = `sha2::Sha512::digest` | Same |
| `ring::digest::digest(...)` | `source:qualified-crypto-api-call` = `ring::digest::digest` | Does not infer hash algorithm from argument |
| `rustls::ClientConfig::builder(...)` | `source:qualified-crypto-api-call` = `rustls::ClientConfig::builder` | Configuration construction does not prove TLS negotiation |

This is **syntax evidence**. It records fully qualified, simple three-segment AST function calls only. It does not infer calls from imports, generic paths, local aliases, macros, comments, strings, methods, virtual dispatch or heuristic text matches. It does not perform type checking or name resolution; a local module with these names could produce the same syntax. `#[cfg]`-disabled code is still syntax evidence. This is a potential site worth independent resolution, **not** proof of an executed algorithm.

For that reason, the collector deliberately emits `RawFactKind::Configuration` under `source:qualified-crypto-api-call`, which the existing pipeline maps into `AssetKind::SourceUse`. It does **not** forge `RawFactKind::AlgorithmUse` with an unrelated IANA or OpenSSL namespace. Separate reviewed source API and algorithm-registry mapping is needed before the latter can be claimed.

Each record has a stable versioned SHA-256 event ID derived from source item, byte offset, 1-based line and column and reviewed API name, plus the exact authorized file-content SHA-256. Metadata contains only fixed semantic tags, **never source excerpts or argument values**. The location may contain private source identity and should be redacted before public export. A source digest does not guarantee the file did not change after being read.

## How to run

From the monorepo root:

```shell
cargo run --locked -p cryptomap --features rust-source --example rust_scoped_source -- \
  crates/cryptomap/examples/fixtures/source crypto_calls.rs \
  2026-10-13T15:00:00Z demo-tenant demo-run-1
```

Replace the root/relative file and timestamp, tenant and run identifiers with **independently authorized** real values. The example intentionally requires an exact filename and prints bounded aggregate counts only. It is also run from the extracted `.crate` in an unrelated clean-room environment, offline.

The bounded supported-parser acceptance suite is:

```shell
cargo test -p cryptomap --test foss_370_rust_source --features rust-source --locked
cargo check -p cryptomap --no-default-features --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Acceptance includes calls versus strings/comments/macros/imports, source hashes and locations, deterministic snapshot replay and tenant separation, unsupported/malformed/UTF-8/oversized inputs, token/depth and undelimited expression-chain budgets (unary, binary, member and generic forms), denied grants, removed files, symlink escape, cancellation and packaged external consumer. CI additionally covers Rust 1.85, Windows, signed-main release supply-chain gates and the frozen Milestone A semantics.

## Deferred

Import and symbol resolution; configuration parsers; control/dataflow analysis; broader API aliases and language support; large-repository traversal; deployment and runtime evidence; PQ readiness, CBOM import/export, and policy/migration projections. Their absence is never automatically evidence that an application contains no cryptography.
