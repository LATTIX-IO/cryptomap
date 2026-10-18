# Milestone B5.4 — bounded, privacy-safe public X.509 profile

**Linear:** FOSS-481, child of FOSS-323. **Status:** developer increment under review, not a merged or published capability until exact-head CI, review and signed-main verification succeed.

## Goals, provenance and default-off behavior

Both existing feature-gated collectors, `certificate-files` and `certificate-store-grants` (through `cryptomap-windows-store` on Windows), reuse **one** RustCrypto `x509-cert 0.2.5` canonical DER decoder. B5.4 adds a strictly allowlisted, deterministic `PublicCertificateProfile` to the already bounded `PublicCertificate` identity; both collectors call `evidence_attributes()` on that same profile. This avoids a second parser and keeps frozen SHA-256 fingerprint, source digest, source-kind and `x509-file:v1`/`x509-store:v1` event IDs intact. No new third-party package is introduced; `const-oid 0.9.6`, already locked transitively by RustCrypto, becomes an explicitly reviewed direct dependency of the SDK for canonical imported OID validation. No new network access, key access or store permission is introduced.

The SDK's existing `CertificateMetadata` is available through `PublicCertificate::certificate_metadata()`. Its issuer, subject and serial are explicitly `Observed::Unknown`; validity and public algorithm profiles are `Observed::Known` only after canonical public DER decoding. To keep frozen certificate asset identities unchanged, the normalization pipeline **does not** replace `AssetKind::Certificate` with `DetailedCertificate`. Instead, it emits evidence-linked, typed-property `certificate:*` observations for the allowlisted B5.4 profile. Pre-B5.4 raw records remain fingerprint-only. Untrusted imported raw observations with incomplete, impossible, or unrecognized versioned profile fields are rejected before entering immutable inventory. Public signature, SPKI and named-curve OIDs are parsed by the pinned RustCrypto `const-oid 0.9.6` implementation and required to round-trip to canonical dotted-decimal text; malformed arcs or leading zeros (e.g. `1..2`, `1.02.3`) cannot poison canonical observations. This does not prove a source's algorithm assertion without independent evidence.

The new attributes are:
- `x509:profile:v1:version`: X.509 certificate version (1, 2 or 3);
- `x509:profile:v1:not-before-utc` and `x509:profile:v1:not-after-utc`: **observed**, RFC3339 UTC timestamps with second precision, not runtime validation;
- `x509:profile:v1:public-key-family`: recognized RSA, EC, Ed25519 or Ed448 algorithm family, absent when Unknown;
- `x509:profile:v1:named-curve-oid`: non-identifying public EC parameter OID, absent when not decodable or when its canonical dotted-decimal string exceeds 128 characters (normalization's metadata field ceiling);
- `x509:profile:v1:public-key-bits`: defined field size only for explicitly recognized secp256r1, secp384r1 and secp521r1, absent otherwise.

Legacy `x509:signature-algorithm-oid`, `x509:public-key-algorithm-oid`, `x509:source-encoding` and `x509:store-target` are retained. **Do not** infer RSA modulus size or cryptographic strength from encoded SPKI BIT STRING length: RSA modulus bit size intentionally remains Unknown pending a reviewed public modulus decoder. Unknown algorithm OIDs and EC parameter values do not invent a named curve, field size or signature validity.

## Temporal semantics

The parser reads one complete DER certificate, verifies round-trip canonical bytes and lets RustCrypto decode all ASN.1 Time values. RFC 5280 certificate validity timestamps through 2049 must be UTCTime; years 2050 onward must be GeneralizedTime. Normalization formats the parser's Z-normalized UTC components as `YYYY-MM-DDTHH:MM:SSZ`. Reverse validity intervals and GeneralizedTime incorrectly encoded for 2049 are rejected as malformed evidence. Dates can be historic, expired, or future; `not-after` is never compared with the machine clock, and no trust verdict is generated.

The pinned `x509-cert 0.2.5` decoder has a **pre-1970 UTCTime representation limitation**. Do not claim acceptance of every RFC 5280 1950–1969 date; this historical compatibility is a separate parser qualification and should fail closed.

## Information minimization

The allowlist never includes Subject/Issuer distinguished names, serial number, SAN, SKI/AKI, public SPKI bytes, public or private key material, identifying extensions, original PEM/DER, certificate signature bytes or raw Windows error strings. Existing `CertificateMetadata` subject, issuer and serial must remain Unknown in default output. The developer profile `Debug` includes ONLY these non-identifying fields. Source item labels are host-issued grants; operators should not use identifying labels because the raw event API retains them for provenance.

The existing `RawLimits` cap (64 KiB decoded DER, file caps, per-store entries/bytes, request-global observation and serialized-byte budgets) remains authoritative. A bad certificate, malformed ASN.1, expired budget, cancellation, unsupported store or interrupted provider must preserve Failed/Partial/NotInspected, never a false clean inventory.

## Deterministic verification

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test -p cryptomap --test foss_481_certificate_profile --features certificate-store-grants --locked
cargo test --workspace --all-targets --all-features --locked
cargo run --locked -p cryptomap --features certificate-files --example certificate_scoped_inventory -- \
  crates/cryptomap/examples/fixtures/certificate rsa.pem \
  2026-10-17T12:00:00Z b54-tenant b54-run
```

The new security corpus verifies malformed/falsified imported profile values are rejected at canonical normalization, typed privacy-sensitive fields remain Unknown, and canonical RSA and EC fingerprints remain frozen, known P-256 curve/bit field size, unknown or modified algorithm/curve identifiers, 2049 UTCTime vs 2050 GeneralizedTime boundary, reversed/malformed dates, expired-but-parseable facts, strict DER size and trailing data, file-versus-provider identity with distinct event provenance, and negative output privacy checks including normalized snapshots. Windows CI exercises the native provider only with ephemeral in-memory stores; it does not inspect real user/machine certificate stores.

**Release gates:** exact-head Linux/Windows/Rust 1.85 CI; RustSec, cargo-deny, SemVer, offline package, SPDX; security review; merged-main signed provenance/SBOM attestation. Both crates remain `publish=false`. FOSS-482/FOSS-483 are separate, blocked follow-ons for opt-in keyed identities and issuer candidate relationships.
