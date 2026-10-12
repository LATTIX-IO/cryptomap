# Cryptomap compatibility policy — pre-1.0 developer SDK

## Versioned surfaces

| Contract | Current implementation | Compatibility policy |
|---|---|---|
| Cargo package | SDK candidate `0.1.1-alpha.1`, unpublished; registry `0.1.0` exists | No stability guarantee prior to a stable release; document every public breaking change |
| Cargo MSRV | Rust 1.85, Edition 2024 | CI checks stable, Rust 1.85 and Windows; changes to MSRV need release notes |
| Canonical asset identity | `asset:v2` | An identity-rule change must be versioned and golden-vector checked; never silently reinterpret old IDs |
| Snapshot JSON schema | `schema_version = 2` | Verify imports and reject unknown schema; no unreviewed widening/loosening of source/tenant verification |
| Raw observation contract | `RAW_CONTRACT_VERSION = 1` | Validate collector version and input records; unknown values must not be silently promoted |
| Collector descriptor | `COLLECTOR_CONTRACT_VERSION = 1` | Treat advertised permissions/modes as metadata, not authority |
| Source evidence | Canonical source digest, run and scope references | Preserve exact tenant/source binding and evidence uncertainty on change |
| Coverage / diff | Explicit failure/partial states, tentative absences | Partial collection never proves deletion or absence |
| CBOM interoperability | Not shipped | No CycloneDX profile or schema compatibility claim for v0.1 |
| Cryptopolicy / cryptoshift | Not shipped | Future versioned, optional adapters; no embedded policy or migration decisions |

## Compatibility rules

1. Breaking Rust public API changes in the pre-1.0 phase require a release note and migration instructions. Use the existing `cargo-semver-checks` CI gate; do not infer a stable API guarantee from green SemVer checks alone.
2. Change canonical asset identity rules, schema or evidence/run authority only with explicit versioning and *frozen* positive/negative fixture vectors. Never auto-update golden baselines merely to make CI green.
3. A SHA-256 snapshot digest establishes self-consistency, not an independently trusted signature, producer authentication or cross-tenant authorization. Importers must validate the expected trusted scope.
4. Preserve both direct/inferred classifications and coverage completeness. Unknown algorithms, ambiguous packages and unsupported source grammars must remain unknown or explicitly unsupported rather than inferred proof.
5. The library is not a sandbox for untrusted in-process collectors, does not guarantee absence of secrets in arbitrary plugin-supplied metadata, and does not perform unapproved networking.
6. Distinguish package dependencies (capability/presence) from source-identified API calls, configured protocol settings and runtime-negotiated algorithm use. A dependency cannot be automatically promoted into observed execution.
7. Lockfile and installation parser support is restricted to documented safe profiles. Parser widening needs adversarial tests for malformed input, duplicate keys, path/tenant mixing, incorrect version resolution, credentials, resource caps and no partial-success promotion.

## Release-governance requirements

Current releases are intentionally disabled via `publish=false`. A release candidate requires reviewed crate ownership, changelog/version, exact-head Linux/Windows/MSRV, clean-room source and custom collector tests, RustSec/cargo-deny, SemVer, a software SBOM, artifact provenance and post-publish validation. The publishing workflow additionally requires an explicit manual dispatch and repository variable, not an automatic push.

Before an actual alpha publication, record the crate checksum, repository commit, schema/asset/collector contracts, compiler version, feature set and deliberately declared limitations. A crate release version cannot be overwritten.

See `docs/milestone-a-release-readiness.md` and FOSS-17/FOSS-19 for outstanding closure gates.
