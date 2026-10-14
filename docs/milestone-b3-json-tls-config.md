# Milestone B3 — bounded JSON TLS configuration evidence

Status: FOSS-371 developer-preview increment. Not general JSON/TLS discovery, not a runtime network probe, and not a release authorization. The independent package still declares `publish = false`. The opt-in `json-tls-config` feature has **no new direct dependencies**, does not enable the Rust AST parser, and preserves snapshot-v2 and Collector contract identity.

## Supported input: exact versioned profile

Only a caller-authorized `.json` file carrying this exact schema is accepted:

```json
{
  "profile": "cryptomap:tls-config:v1",
  "tls": {
    "versions": ["1.2", "1.3"],
    "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"]
  }
}
```

Required root keys: `profile` and `tls`. `tls` must be an object; `versions` and `cipher_suites` are optional arrays defaulting to empty. An empty `tls` object is successfully inspected with `InspectedNoObservation`. **All unknown fields, duplicate JSON object keys, duplicate list values, nulls, invalid types and non-whitelisted names cause `MalformedSource` and `Failed` coverage**, not clean absence. An otherwise valid document with a different versioned profile marker is `Unsupported`. A missing marker is malformed.

Supported exact strings (names must match case and spelling):

- TLS protocol versions: `1.2`, `1.3` (maximum two)
- Configured suite identifiers: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (maximum eight)

These are only accepted *source strings*, not judgments of compliance, compatibility, deployment or configuration validity for a TLS implementation. The collector does not attempt to verify whether a selected cipher suite can actually negotiate under a selected protocol version.

## Evidence and limitations

For each approved version, the collector emits `RawFactKind::Protocol { family: "TLS", version, state: Configured }`; for an approved suite it emits `RawFactKind::Configuration { property: "tls:configured-cipher-suite", value: whitelisted_name }`. Each fact is backed by direct **configuration-source evidence** (`source:evidence-semantics = configured-only`), never the `Negotiated` state, an `AlgorithmUse` claim or inferred assurance.

The source locator intentionally uses the exact authorized source item with `offset = None`, `line = None`, `column = None`. No inaccurate field spans are invented. Event IDs are versioned SHA-256 identities over the source item, actual file SHA-256, whitelisted fact type and value. Source SHA-256 enables content correlation, but is **not** a producer signature or proof of deployed config. The normalized `SourceUse` identity is document-level, which is consistent with the lack of field-level spans.

Only a trusted host may supply scope, run and identity. Use `CollectionScope::grant_file(RawSourceKind::Source, item, root, relative, max_bytes)` and `orchestration::collect_normalized` with an independently pinned descriptor/tenant identity. Source authorization is enforced before reading any requested file. Trusted collectors that retain a scope internally expose its exact reference through the compatible `Collector::matches_invocation_scope` predicate without exposing file grants; scoped and host-pinned batch preflight reject any other scope object even when the two objects have the same tenant label and source IDs. This also repairs the older Rust-source collector's trust boundary. File handles are rooted and revalidated on each use; symlink traversal and grant expansion are prohibited. An in-process collector is **not** an OS sandbox.

The collector reads at most **16 KiB** per file, rejects unsupported filename extensions and validates JSON under strict serde struct field/duplicate checks. Deserialization bounds versions to two and suite entries to eight *while reading the arrays*, not after unbounded allocation. JSON depth is bounded by the serde_json parser. All accepted output metadata values are fixed whitelisted strings, never raw secrets, code excerpts or arbitrary error messages. Unknown/secret-bearing configuration fields are rejected without echoing their values. Remaining output source IDs may still be identifying; apply the SDK's redaction API before external publication.

For a valid source with insufficient raw observation budget, the collector rejects that file as `Failed`/ `ResourceLimit` before writing any observations. Source-level malformed/unsupported inputs preserve independent successful sources as a `Partial` run. A forged event or aggregate sink budget failure remains fatal. Cancellation produces no false clean coverage; if interrupted after some facts, the source is `Partial`, otherwise `NotInspected`.

## Run from the workspace or a packaged .crate

```shell
cargo run --locked -p cryptomap --features json-tls-config --example json_scoped_tls -- \
  crates/cryptomap/examples/fixtures/config tls.json \
  2026-10-13T15:00:00Z demo-tls-tenant demo-tls-run
```

The example grants **only that file** and prints a verified snapshot identity and bounded counts, no source values or snippets. The offline clean-room package gate copies the fixture and runs the example through the extracted `.crate`. No package lifecycle scripts, TLS negotiation or network access are initiated.

```shell
cargo test -p cryptomap --test foss_371_json_tls_config --features json-tls-config --locked
cargo check -p cryptomap --no-default-features --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

The B3 regression suite includes exact approved values, a normalized, independently scope-verified snapshot, determinism under source permutation, tenant mismatches, wrong/missing profile, duplicate keys and list items, secret-key rejection, UTF-8/JSON invalidity, size and list bounds, cancellation, symlink denial, unsupported extensions, post-grant file deletion, input modification and no inferred negotiation/algorithm execution. Windows and Rust 1.85 are independent CI gates.

## Deferred

General JSON/TOML/YAML configuration parsers, framework-specific TLS profiles, cipher negotiation/compatibility verification, automatic source enumeration, key/certificate extraction, exact field span attribution, OTEL/live telemetry, compliant-policy projection, and CBOM export are explicitly out of scope. A failed or unsupported file never proves the absence of cryptography.
