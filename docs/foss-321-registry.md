# FOSS-321: bounded exact-alias normalization registry (increment 1)

## Contract

The public `cryptomap::registry` module resolves a caller-supplied cryptographic identifier in the explicit context **(namespace, kind, raw)**. All three fields are part of its identity. An exact, case-sensitive key maps to the canonical profile, family, mapping rule, normative reference and registry version. Unknown keys preserve namespace, kind, raw spelling and version for future reprocessing. Neither case-folding, substring matching nor semantic inference is allowed.

The built-in registry initially covers selected IANA TLS cipher suites and groups, RFC 4055 / RFC 5480 X.509 OIDs, OpenSSL SHA-256 and SSH Ed25519. The registry is *not* an exhaustive standards database. Registry sources are recorded on every built-in `Mapping`; `Resolution::Known` carries source metadata to evidence consumers. Exact lexical matching is not proof that the cryptographic operation was configured, negotiated, or executed.

Some algorithm identifiers, including the RSASSA-PSS and EC public key X.509 OIDs, require additional ASN.1 parameters to distinguish a concrete profile. The built-in canonical labels explicitly indicate **parameters-required** or **curve-unspecified**. Do not promote those partial labels into a fully specified algorithm or key profile. Parameter parsing and raw-to-canonical evidence integration belong to FOSS-320.

## Extension trust boundary

`Registry::builtin()` constructs the fixed, versioned standards registry. `Registry::register` only accepts `Namespace::Extension(owner)` mappings; a caller cannot create or shadow a mapping in the built-in standard namespaces. Existing exact keys are immutable and collisions return `RegistryError::Collision`. Malformed canonical values return `InvalidCanonical`; other malformed fields return `InvalidInput`.

The registry never fetches remote records or enumerates any local resource. Identifier and metadata strings have a 256-byte ceiling and reject control characters and surrounding whitespace. Registry updates require an explicit code-reviewed release and corresponding `REGISTRY_VERSION` revision. `Registry::digest()` hashes the version and sorted semantic mappings in deterministic order; it is not an authenticity signature. Do not accept an untrusted digest as proof of provenance.

## Example

```rust
use cryptomap::registry::{Kind, Namespace, Registry, Resolution};
let registry = Registry::builtin();
let resolution = registry.resolve(&Namespace::TlsCipherSuite, &Kind::CipherSuite, "0x1301")?;
match resolution {
    Resolution::Known { canonical, source, .. } => {
        assert_eq!(canonical, "TLS_AES_128_GCM_SHA256");
        assert!(source.contains("iana.org"));
    }
    Resolution::Unknown { .. } => panic!("expected an exact built-in alias"),
}
# Ok::<(), Box<dyn std::error::Error>>(() )
```

## Increment 1 acceptance

- Exact IANA TLS suite/group and X.509 OID mapping with a documented rule and source.
- Namespace and kind prevent ambiguous cross-domain aliases and preserve unknowns.
- Known results preserve both provenance dimensions and the authoritative mapping source.
- Bad identifiers and canonical values produce distinct typed errors; standard namespaces cannot be extended through the public API.
- Permuted insertions return the same registry digest; serialized resolutions preserve provenance.
- Rust 1.85, Linux strict lint/docs/tests and Windows CI all required before merging.

## Deferred—not claimed complete

FOSS-320 owns raw source validation, typed algorithm parameters, evidence correlation, conflict handling, canonical snapshot finalization, coverage, and cancellation/backpressure. FOSS-322..326 own five reference collectors that will consume this central registry via FOSS-320. Broader mappings, formal version-to-version golden fixture migrations and semantic equivalence tests belong to subsequent FOSS-321 increments before the full Linear story can be closed.
