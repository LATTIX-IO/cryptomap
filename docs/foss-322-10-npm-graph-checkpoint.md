# FOSS-322.10 — Verified npm graph checkpoint and invalidation

## Public API and design contract

`checkpoint_npm_projection` constructs a versioned, deterministic `NpmProjectionCheckpoint` only after verifying the canonical inventory's tenant scope, exact authorized package.json and package-lock.json, independent direct/confirmed collection evidence, completeness of the lock collection, source SHA-256 and deterministic installation-path transitive edges. It rejects a source snapshot that has not yet been fully projected into canonical npm path assets and DependsOn edges.

A checkpoint holds version 1, scope ID, exact manifest and lock source IDs, canonical snapshot ID, both SHA-256 source digests, and a domain-separated SHA-256 fingerprint of the typed tuple. It contains no raw manifests, credentials, registry URLs or package content. The typed tuple prevents delimiter confusion. The fingerprint is an integrity checksum, **not** a signature, authorization credential or secret.

`verify_npm_checkpoint` rejects unsupported version, mismatched tenant, tampered fields, stale file content, wrong source bindings, invalid canonical snapshot, incomplete/partial collection evidence and missing graph edges. It re-authorizes and re-reads the caller's exact file grants, recalculates complete canonical graph projection and requires byte-for-byte checkpoint equality. A changed source requires fresh collection and projection before minting a new token. Checkpoint verification does not touch arbitrary filesystem locations, execute npm, use the network, or silently project missing evidence.

## Unit, regression and security acceptance

- Deterministic minting, JSON serialization/roundtrip, immutable canonical snapshot digest, stable source fingerprints and successful validation of an unchanged fully projected graph.
- Reject pre-projection snapshots, forged lock digest, forged canonical snapshot ID, changed version, changed source item, changed tenant, modified manifest, modified lockfile, and any invalid or incomplete source provenance.
- Retain existing FOSS-322.7/.8/.9 authorization, scope, path-identity, replay, malicious nested-package, resource-limit and CI regression suites.

## Merge requirements

Exact final PR-head GitHub Actions: Linux locked fmt, check, strict Clippy, unit/integration/security/regression tests, docs, package, RustSec and dependency policy/SemVer; Windows compatibility; Rust 1.85 MSRV; all actionable review findings resolved. Do not merge on earlier-head checks.

## Remaining FOSS-322 scope

This increment adds revalidation and invalidation semantics, not a delta-scan or resumption executor. Broader Cargo TOML grammar, workspaces, npm aliases/optional/peer dependencies, non-exact version requirements and true incremental scan scheduling remain outstanding; parent FOSS-322 remains In Progress.
