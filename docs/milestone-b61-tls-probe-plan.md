# Cryptomap B6.1 — Exact-grant TLS probe planning

**FOSS-510**, child of **FOSS-324**. The feature `tls-probe` is **off by
default** and performs no TLS handshake, DNS resolution, network connection,
certificate validation, or protocol observation.

B6.1 is a *capability contract*, not an active TLS network collector.
The host authorizes exact, bounded endpoint targets by
`CollectionScope::grant_endpoint(NetworkTarget)` with one host/port,
optional explicit SNI, and a finite set of pinned IP addresses.
`TlsProbePlan::prepare` then accepts only a
`RequestedSource { kind: RawSourceKind::TlsEndpoint, item: exact_target_id }`
from that same scope; it borrows the existing `AuthorizedEndpoint`.
No implicit SNI fallback, dynamic address discovery, redirects, or
additional connection destinations are permitted.

The plan pins finite budgets for TCP connection timeout (<= 30 seconds),
TLS negotiation timeout (<= 30 seconds), handshake bytes (<= 1 MiB), public
peer-certificate DER aggregate (<= 1 MiB and <= handshake budget), chain
length (<= 16), and a maximum 32 candidate IP attempts. The default plans
for one attempt, three seconds TCP, five seconds handshake, 256 KiB
handshake, 128 KiB chain, and eight certificates.

**Important:** These budgets are validated planning inputs, not evidence of
enforcement by an actual TLS backend. FOSS-511 must enforce the same budgets
in all handshake/parser/transport paths before B6.2 claims operational
readiness. The plan authorizes *destinations*, never peer authenticity.

## Developer test

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test -p cryptomap --test foss_510_tls_probe_plan --features tls-probe --locked
cargo test --workspace --all-targets --all-features --locked
```

All tests operate on deterministic in-memory authorization data or a local
unconnected loopback listener, and prove plan construction causes no network
activity. Cross-platform Windows and Rust 1.85 validation are required.

## Security boundaries

- `NetworkTarget::new` rejects wildcards and missing/invalid IP pins.
- No global DNS, fallback to non-pinned destinations, or implicit IP sweep.
- SNI remains exactly the granted SNI; absent SNI is not inferred from host.
- The plan has no `connect` method. B6.2 must call
  `AuthorizedEndpoint::connect` with the same exact IP and port and
  enforce cancellation and finite handshake work.
- A valid plan does **not** mean the destination was reached, a TLS version
  was negotiated, or the server was authenticated.
- Existing canonical inventory schema, Evidence/Observation and trust
  relationships are unchanged. No added dependency, default feature,
  or crates.io publication.
