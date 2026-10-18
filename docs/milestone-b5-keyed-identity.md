# FOSS-482 — B5.5 host-keyed X.509 identity candidate hints

This experimental opt-in uses `certificate-identity` with `certificate-files`
or `certificate-store-grants`. Ordinary public profiles remain unchanged.

The caller creates `CertificateIdentityAuthority::new(scope.id().clone(), tenant,
key_version, key)` with a host-generated 32-byte secret and explicitly
attaches it via `with_identity(&authority)`. Keys, tenants and key versions
are never accepted through untrusted `CollectionRequest.options`. The
authority cannot be debug-printed or serialized and its owned key is zeroized
at drop. Callers are responsible for securing their original key buffers.

Each supported and authenticated record receives up to three `x509:identity:v1:*` opaque
HMAC-SHA256 attributes. The same supported, unambiguous canonicalized DN receives the same hint
whether it is observed as a subject or issuer, and serial pseudonyms include
the issuer's normalized DN comparison key. Domains, exact collection scope
and length-prefixed input components separate
DNs from issuer-bound serials. Existing certificate fingerprints, AssetIds,
event identities, public attributes, and direct evidence remain unchanged.

**Security semantics:** hints are tenant/key-version-scoped *candidates*,
not anonymous global identifiers, verified issuance, path validation,
signature verification, or trust. Anyone with the tenant key can test guesses.
Different keys or versions must not be compared, and loss/rotation does not
provide automatic alias migration.

**Deliberately bounded equivalence:** the supported subset of RFC 5280
section 7.1 normalizes known ASCII DirectoryString attributes using either
PrintableString or UTF8String encoding, ASCII case folding and insignificant
space folding. It preserves RDN sequence and SET boundaries and sorts only
within a multivalued RDN. Unknown OIDs, unsupported IA5/BMP/Teletex/
Universal encodings, non-ASCII Unicode requiring full LDAP StringPrep,
duplicate normalized attributes, overbudget/ambiguous values and empty DNs
remain Unknown. This avoids incorrectly *creating* issuer matches. It is
not a complete RFC 4518 Unicode comparison implementation. No SAN, SKI,
AKI, plaintext DN, raw serial, SPKI material, or secret is projected.

**Cryptographic provenance:** every record that contains identity hints has
an `x509:identity:v1:namespace` tag and an HMAC receipt signed over the
complete raw record, including scope-qualified key context, run, source,
fingerprint and attributes. `pipeline::normalize` rejects any identity
attributes: the host must supply the original in-process capability to
`pipeline::normalize_with_identity` or call
`orchestration::collect_normalized_with_identity`. The normalizer recomputes
the receipt before emitting canonical observations. Receipt values are
verification metadata, not candidate graph edges; the key namespace is
preserved for B5.6 correlation fencing. Replaying a token without its exact
authenticated event is rejected. A trusted host must not distribute keys
to third-party collectors; in-process authority is not an OS sandbox.

**Memory limitation:** `Zeroizing` protects the authority-owned key
on drop and each bounded per-attribute, RDN-group and final plaintext
comparison buffer throughout DN normalization, including early error exits. Pinned
RustCrypto HMAC 0.12.1 itself does not guarantee zeroization of all
transient internal SHA-256/HMAC working state; process-memory compromise
remains outside this in-process memory erasure guarantee. This finding
requires independent security-risk disposition before merge.

**Collection and release:** opt-in always requires existing exact file or
store grants; all current byte, count, cancellation and coverage rules remain.
Untrusted raw records pass a separate strict opaque attribute allowlist at
normalization. The two crates remain `publish = false`. No real Windows
store access is authorized by CI, and this capability does not certify the
separate Windows adapter release (FOSS-486).

## Qualification

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo test --locked -p cryptomap --features certificate-identity,certificate-store-grants --test foss_482_certificate_identity
cargo doc --locked --workspace --all-features --no-deps
```

Release gate additionally requires native Windows ephemeral-memory tests,
Rust 1.85, RustSec, dependency policy, semver, independent SPDX validation,
offline packaged consumers and an independent security review. No merge until
exact-head CI, reviewed dependency changes and successful post-merge signing.
