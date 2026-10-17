# Milestone B5.3 — opt-in Windows public certificate-store evidence

**Issue:** FOSS-468. **Status:** implementation under review; this document does not claim a merged or published release.

## Architecture and trust boundary

This is an additive, **separately packaged** workspace crate, `cryptomap-windows-store`. Cryptomap's original `#![forbid(unsafe_code)]` remains unchanged. The companion crate contains the narrowly scoped, documented unsafe Win32 API calls. The main `cryptomap` library does **not** depend on this Windows adapter, and non-Windows builds do not compile or link CryptoAPI.

The opt-in crate exposes `WindowsCertificateStoreBackend::new(&scope, exact_item)`, which captures the exact trusted grant and refuses direct provider calls that try to inspect any other target. It implements the safe, injection-based `PublicCertificateStoreBackend` trait from `cryptomap::collectors::certificate_store`. The host creates a typed `CertificateStoreGrant` in an exact `CollectionScope` and invokes `CertificateStoreCollector::new(scope, &backend, observed_at)`. Requested items only identify grants; they cannot select or expand store targets through options. Collector provenance remains host-pinned to the exact same scope object.

Only these stores are available: `CurrentUser/My` and `LocalMachine/My` (the latter only after an explicit additional host grant). The Win32 adapter opens **only the explicitly selected physical local system REGISTRY store** using `CERT_STORE_PROV_SYSTEM_REGISTRY_W` plus `CERT_STORE_READONLY_FLAG` and `CERT_STORE_OPEN_EXISTING_FLAG`. This deliberately excludes logical aggregation of remote/group-policy/enterprise physical stores, broad Root/CA enumeration and implicit creation of missing registry stores. The Win32 ACL is independently enforced; a typed grant is not an OS privilege. No network access, revocation/OCSP/CRL fetch or native verification is performed.

Win32 handles are always wrapped with RAII. The enumerator takes ownership of the previous context; the wrapper transfers ownership before every enumerator call to prevent use-after-free/double-free. On cancellation, early error and over-budget, the remaining context and handle are closed. The adapter checks encoded-context pointer and byte count **before** creating a borrowed slice; raw DER is never returned to the application or put into diagnostics.

## Invariants

- A public certificate is parsed through the **same** RustCrypto DER decoder used by B5.1 file evidence: canonical DER only; no trailing bytes, BER or oversized encodings. The canonical asset fingerprint is SHA-256 of original DER; file and store observations of that DER share asset identity but have distinct source/event provenance.
- No private key, certificate subject/issuer/serial, provider properties, file paths or raw DER are emitted into output. Only public algorithm OIDs, fingerprint, exact typed store target and bounded evidence metadata.
- The **native** adapter checks the 64 KiB per-certificate public DER size before borrowing and forwarding Win32 memory. The **safe collector** enforces every grant's `max_entries` and cumulative `max_public_bytes`, plus the request-global `RawLimits.observations` and `total_bytes` sink limit. The latter is serialized observation size, **not** public DER inspection size.
- A denied, malformed, over-budget or incomplete enumeration produces typed Failed/Partial coverage and keeps already verified evidence without claiming a clean absence. Empty stores are `InspectedNoObservation` only after the native enumerator explicitly completes. Provider errors are sanitized, never raw Windows strings.
- Cancellation and monotonic deadline checks are cooperative between records; an individual synchronous OS call cannot be forcibly preempted by this collector. Concurrent store mutation is not a transactional snapshot and may produce incomplete coverage; operators must not interpret a partial result as proof of absence.
- The native backend is a trusted in-process component; to execute *untrusted* provider code, use OS process isolation.

## Automated acceptance without touching real stores

```sh
cargo test -p cryptomap --test foss_468_certificate_store_backend --features certificate-store-grants --locked
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

On Windows, `cargo test -p cryptomap-windows-store --locked` creates and destroys only an **ephemeral in-memory CryptoAPI store**, inserts deterministic public RSA and EC DER fixtures and exercises the *real* Win32 enumeration/cursor path. It verifies exact returned bytes and interrupted/empty enumeration cleanup. It does not write or read any user's CurrentUser/My or LocalMachine/My store. Portable fake-backend tests exercise source grants, malformed trailing DER, duplicate contexts, budgets, interruption and partial failures. CI validates Rust 1.85, Linux, Windows, RustSec, SPDX, dependency policy, package consumer and SemVer.

### Explicitly authorized manual CurrentUser/My UAT (optional)

This command does not run as part of CI. It prints only counts and coverage; no certificate names, key references, serial numbers, fingerprints or raw DER.

```powershell
cargo run --locked -p cryptomap-windows-store --example read_user_store -- --authorize-current-user-my 2026-10-17T14:00:00Z
```

Run only with informed operator approval and an accurate RFC3339 timestamp. This does not collect LocalMachine by default. To inspect machine stores, a separate host-authorization workflow must be built and reviewed; no implicit flag to do so is provided in the example.

## Release restrictions

Both the SDK and Windows adapter remain `publish = false`. No crates.io publication, store mutation, administrator elevation, production credentials or protected environment change is made. The FOSS-468 merge requires completed exact-head Linux/Windows/Rust 1.85 CI, substantive security review and **post-merge main-only signed provenance/SPDX verification**.
