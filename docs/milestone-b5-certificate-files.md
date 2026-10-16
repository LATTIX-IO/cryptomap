# Milestone B5.1 — public-only, exact-file X.509 certificate evidence

Status: FOSS-406 independent implementation increment of parent FOSS-323. Full FOSS-323 also requires a distinct Windows store integration increment; **no store enumeration is claimed here**.

## Trust and privacy boundary

The host explicitly grants an exact certificate file with `RawSourceKind::Certificate` and supplies a tenant identity, timestamp and run ID. The passive collector does not find arbitrary files, enumerate stores, make network connections, execute certificate contents, collect private key bytes or establish certificate trust. Parsing public cert bytes is **not** signature verification, hostname authentication, TLS negotiation, revocation evaluation or compliance analysis.

A default-off Cargo feature `certificate-files` enables `x509-parser 0.18.1` with no verification features. This is a maintained permissively licensed RFC 5280 parser with defensive parser limits and fuzzing; it must remain Rust 1.85 compatible along with *all* resolved transitive dependencies. The exact `Cargo.lock` must be generated with Cargo, reviewed for MSRV, licenses and RustSec, and checked by software SPDX before merge.

## Supported source profiles

- Explicit file extensions: `.pem`, `.der`, `.crt`, `.cer` under a granted file path. The grant identity is authoritative; no guesses from request item names.
- PEM: require exact `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` armor, with bounded ASCII base64 payload; the decoder's more permissive footer handling is not an authorization or validation shortcut. Only approved certificate blocks may be parsed. Leading/trailing ASCII whitespace is permitted. Multiple public certificates are allowed up to **16** per file. Duplicates or mixed/private-key PEM labels fail the entire file without emitting partial false-success facts. No private block is base64-decoded.
- DER: exactly one RFC 5280 X.509 certificate with no trailing data. No implicit PKCS#7, PKCS#12, CSR or key decoding.
- Maximum file: **256 KiB**; maximum decoded certificate: **64 KiB**. Scope-level grants and raw observation limits still apply before I/O and emission.

Each accepted certificate generates one `RawFactKind::Certificate { fingerprint_sha256 }` with SHA-256 of its canonical DER bytes. Public signature and public-key algorithm OIDs are bounded and supplied only as source-backed metadata. Event IDs are digest-bound to the file source, source digest and fingerprint. A given cert in PEM/DER yields the **same canonical fingerprint identity** but distinct source/event provenance. The collector does not claim validity/expiry status, issuer trust or private key availability.

Malformed, unsupported, oversized, denied or ungranted files emit explicit failed/unsupported/partial coverage and safe typed diagnostics. Source text, private key bodies, public cert blobs and unvalidated subjects/serial numbers are never copied to evidence output or diagnostics.

## Developer-facing example

From repository root after locking the parser dependency:

```sh
cargo run --locked -p cryptomap --features certificate-files \
  --example certificate_scoped_inventory -- \
  crates/cryptomap/examples/fixtures/certificate rsa.pem \
  2026-10-16T12:00:00Z cert-tenant cert-run

cargo test -p cryptomap --features certificate-files --test foss_406_certificate_files --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo +1.85.0 test --workspace --all-features --locked
cargo package -p cryptomap --locked
bash scripts/verify-packaged-consumer.sh
```

CI must additionally run RustSec, cargo-deny, software SPDX exact-direct-dependency checks, SemVer, Windows, strict rustdoc and signed-main provenance. Fixtures are intentionally **public certificates only**; generated private keys were destroyed before committing fixture assets.

## Acceptance and remaining scope

This increment has RSA and EC public fixtures, independent OpenSSL SHA-256 fingerprint vectors, DER/PEM identity comparison, duplicate/invalid/private header negatives, source size/count/observation budgets, grant/cross-scope and symlink rejection, cancellation and partial coverage. An empty/unparseable file is *Failed*, not proof of no cryptography.

**Explicit exclusions:** Windows/macOS/Linux machine-store enumeration, CA chain validation, OCSP/CRL, private key parsing/export, active TLS probing, user directory scanning, compliance scoring, signature authenticity, registration or crates.io publication. FOSS-323 remains open until Windows store metadata and the broader interoperability DoD are implemented.

Never merge without an exact-head green Linux/Windows/MSRV CI suite, independent security review, a reproducible Cargo.lock and post-merge main signed SLSA/SPDX checks; preserve `publish = false` and frozen snapshot-v2 identity.
