# FOSS-482 — B5.5 host-keyed X.509 identity candidate hints

This experimental opt-in uses `certificate-identity` with `certificate-files`
or `certificate-store-grants`. Ordinary public profiles remain unchanged.

The caller creates `CertificateIdentityAuthority::new(scope.id().clone(), tenant,
key_version, key)` with a host-generated 32-byte secret and explicitly
attaches it via `with_identity(&authority)`. Keys, tenants and key versions
are never accepted through untrusted `CollectionRequest.options`. The
authority cannot be debug-printed or serialized and its owned key is zeroized
at drop. Callers are responsible for securing their original key buffers.

Each accepted record receives up to three `x509:identity:v1:*` opaque
HMAC-SHA256 attributes. The same canonical DER DN receives the same hint
whether it is observed as a subject or issuer, and serial pseudonyms include
the issuer's DER DN. Domains and length-prefixed input components separate
DNs from issuer-bound serials. Existing certificate fingerprints, AssetIds,
event identities, public attributes, and direct evidence remain unchanged.

**Security semantics:** hints are tenant/key-version-scoped *candidates*,
not anonymous global identifiers, verified issuance, path validation,
signature verification, or trust. Anyone with the tenant key can test guesses.
Different keys or versions must not be compared, and loss/rotation does not
provide automatic alias migration.

**Deliberately conservative equivalence:** only exact canonical DER DN
equivalence is emitted, not RFC4514 textual spelling equivalence, Unicode
normalization, case folding, cross-string-type matching or semantic RDN
normalization. These are potential false negatives, not grounds to guess
matches. No SAN, SKI, AKI, DN plaintext, raw serial, SPKI material, or secret
is intentionally projected. Empty DNs remain Unknown. B5.6 must distinguish
candidate relationships from `IssuedBy`/`ValidatedBy` edges.

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
cargo test --locked -p cryptomap --features certificate-identity --test foss_482_certificate_identity
cargo doc --locked --workspace --all-features --no-deps
```

Release gate additionally requires native Windows ephemeral-memory tests,
Rust 1.85, RustSec, dependency policy, semver, independent SPDX validation,
offline packaged consumers and an independent security review. No merge until
exact-head CI, reviewed dependency changes and successful post-merge signing.
