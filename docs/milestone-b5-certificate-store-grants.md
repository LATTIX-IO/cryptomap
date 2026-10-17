# Milestone B5.2 — typed, inert certificate-store authorization

**Status:** FOSS-467 developer increment of FOSS-323. Does NOT enumerate Windows stores, access private keys, establish certificate trust, or claim any public certificate was observed. Native read-only Windows enumeration remains FOSS-468.

## Security model

`certificate-store-grants` is a default-disabled additive Cargo feature that introduces a distinct `RawSourceKind::CertificateStore`, separate from the existing file-grant `RawSourceKind::Certificate`. The new typed API is cross-platform and has no Windows DLL, system registry, provider handle, filesystem or network dependency.

A **trusted host** constructs `CertificateStoreTarget` with explicit `CurrentUser` or `LocalMachine` location and the **only supported** store name `My`, then calls `CertificateStoreGrant::new(target, max_entries, max_public_bytes)` and `CollectionScope::grant_certificate_store(exact_item, grant)`. Canonical target identities are `certstore:v1:CurrentUser/My` and `certstore:v1:LocalMachine/My`; these are inert labels, **not proof that either store is available, readable or approved by the OS**. Root, CA, machine-wide defaults, wildcard, remote and service stores are unsupported. The host must separately authorize machine access; simply constructing a typed LocalMachine grant does not convey Windows privileges.

The request contains the **host-issued exact item ID** and source kind, never a derived store URI, user-supplied path, registry key or implicit fallback. Validation occurs before any collector invocation, including raw, isolated, normalized and multi-run batch routes. A collector must be pointer-bound to the same host scope object. A file grant of any source kind, logical grant or network target cannot reuse a certificate-store item label (in either grant-creation order), and a legacy `grant_logical(Certificate, ...)` cannot authorize a `CertificateStore` request. There is no wildcard expansion or discovery.

## Resource and evidence boundaries

- `max_entries` must be in 1..=1024, and `max_public_bytes` in 1..=16 MiB. A deserialized grant is revalidated before storage in the scope.
- For **store-only requests**, the request-wide `RawLimits.observations` may not exceed the sum of explicitly granted per-store `max_entries`; each store's limit remains separate. Mixed-kind requests share the global sink budget but cannot use a store grant to increase another source's authority. The future native adapter must independently enforce **each store's** entry limit. `RawLimits.total_bytes` separately limits serialized observations and is **not** interchangeable with decoded public DER size. FOSS-468 must enforce `max_public_bytes` per store independently before decoding and emitting.
- No store implementation is registered at B5.2. The inert test adapter returns typed **Unsupported** or **NotInspected** coverage with no observations. It does not report an empty store as inspected. Future FOSS-468 evidence must reuse canonical SHA-256 over complete original public DER, maintain distinct store provenance/event IDs, and avoid exposing subject names, serial numbers and private material in diagnostics.
- Callers running untrusted collector code must use process isolation; the scope API is a cooperative in-process authorization contract, not an OS sandbox. Cancellation and source-scope failure cannot become a false clean inventory.

## Developer verification

```sh
cargo run --locked -p cryptomap --features certificate-store-grants --example certificate_store_authorization
cargo test -p cryptomap --features certificate-store-grants --test foss_467_certificate_store_grants --locked
cargo check --workspace --all-targets --all-features --locked
cargo test --workspace --all-targets --all-features --locked
```

The example prints the exact authorized target and finite budgets but performs no platform operation. Security regressions cover wrong hive/store, malformed names, duplicate/colliding file and store labels, missing grants, cross-scope replay, mutated serialized grants, over-budget requests, cancellation and mixed-batch preflight without fake provider execution. Linux, Windows and Rust 1.85 CI run the same inert conformance tests. The repository remains `publish = false` and source-bound provenance is verified only after merge to `main`.
