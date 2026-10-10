# FOSS-2 canonical cryptographic inventory: acceptance evidence

Story: https://linear.app/lattix/issue/FOSS-2/implement-canonical-cryptographic-inventory-model
Integration review: https://github.com/LATTIX-IO/cryptomap/pull/3

## Architecture

`Asset` represents a canonical logical asset. `Observation` represents an immutable, evidence-backed fact about an asset. `Evidence` identifies collector/run/source, time, confidence and inference rule where applicable. `CollectionRun` and `CoverageRecord` distinguish actual inspection from source omission/failure. `InventorySnapshot` is a verified, versioned canonical inventory artifact.

The public model records observed cryptography. Policy compliance and PQC migration prioritization are intentionally outside this user story.

## Child issue trace

| Linear issue | Code surface | Evidence |
|---|---|---|
| FOSS-3 | `src/lib.rs`, manifest | `tests/inventory.rs`; Cargo.lock; PR #3 |
| FOSS-301 | `src/metadata.rs`, AssetKind | Detailed asset metadata, Rustdoc, `tests/model_contract.rs` |
| FOSS-302 | `src/identity.rs` | Scoped use-site/provider IDs; cross-platform golden ID test; `tests/model_contract.rs`, `tests/properties.rs` |
| FOSS-303 | `src/validation.rs`, Evidence, Observation | RFC3339, evidence-run matching, inference requirement; negative fixtures |
| FOSS-304 | RelationshipKind/validation | Type-constrained endpoints, dangling-ref rejection, graph traversal fixtures |
| FOSS-305 | InventoryBuilder::ingest_candidate/add_asset | Deterministic identity, idempotent identical candidates, no fuzzy merging, collision rejection |
| FOSS-306 | Scoped/temporal conflict processing | Independent evidence sets, UTC-hour context, set-valued properties; `tests/model_contract.rs` |
| FOSS-307 | `src/coverage.rs` | Explicit collection scope, completeness, collector/run metadata and coverage negative tests |
| FOSS-308 | `src/validation.rs`, `src/privacy.rs` | Bounded metadata, known secret-marker rejection, report-local anonymized export test |
| FOSS-309 | InventoryBuilder, InventorySnapshot::verify/from_json_verified | Canonical SHA-256 snapshot, digest/schema/ref checks, tampering test |
| FOSS-310 | ChangeSet | Asset/observation/evidence/confidence/relationship/conflict/coverage deltas, tentative removals |
| FOSS-311 | `src/query.rs` | Typed asset, algorithm, protocol, package, provider, certificate, endpoint, confidence/time/source/conflict/relationship queries; depth/result bounds |
| FOSS-312 | `tests/{inventory,model_contract,properties}.rs` | Golden identity; 64 seeded order permutations; negative tests; cross-platform CI matrix |
| FOSS-313 | `.github/workflows/ci.yml`, Cargo.lock | Format, compile, Clippy, tests, docs, RustSec, cargo-deny, semver, Rust 1.85 and Windows matrix |

## Canonical identity and schema contracts

- Asset identity version: `asset:v2`; domain separator `cryptomap:asset:v2`.
- Snapshot schema version: `2`.
- Identical normalized inputs and scope yield identical asset IDs.
- Protocol and extension assets require a concrete use-site.
- Keys and key stores require a concrete provider-instance identity.
- Identity ambiguity fails instead of merging multiple assets.
- SnapshotId is SHA-256 over the canonical serialized semantic data, including evidence/coverage. Hashes check accidental/tampering inconsistency but are **not digital signatures**.

## Privacy and trust assumptions

- The canonical model does not include private/symmetric key material fields.
- Validation rejects common private-key block markers and enforces metadata size limits. It cannot recognize every form of secret; source collectors MUST NOT feed secrets into the inventory.
- Source paths, endpoint identifiers and key-provider metadata can themselves be sensitive. Use the redacted report API for privacy-minimized reviews. Its aliases are report-local and intentionally cannot be used as stable cross-export IDs.
- Provenance identifies source and collector; **authentication of collectors** is a host/integration responsibility and is not claimed by this library.
- Conflicts are based on asset/property, optional context and UTC-hour bucket. Set-valued configured profiles are not scalar conflicts. A source requiring finer temporal reasoning must provide a suitable session/context identifier; a one-hour bucket is not a universal temporal ontology.
- Evidence absence during a partial collection is not evidence of asset removal.

## Release/closure gates

1. All tests pass with `--locked` and on the declared Rust 1.85 MSRV.
2. Windows compatibility job passes.
3. Formatting, check, Clippy with warnings denied, and documentation pass.
4. cargo-audit, cargo-deny and cargo-semver-checks pass.
5. Reviewer verifies child issue acceptance criteria, canonical schema stability and safe error/unknown handling.
6. PR remains draft/unmerged until successful review. Linear Done state must correspond to reviewed implementation, not merely a code commit.
