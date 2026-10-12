# FOSS-322.13 — Strict, bounded npm generation recovery bundles

## Goal

Provide an explicit host-managed interchange format for the verified immutable npm generation introduced by FOSS-322.12, without restoring a persisted snapshot as trusted authority. The caller supplies bytes, live exact-grant \`CollectionScope\`, maximum encoded size, inventory and source budgets, and an expected live generation sequence.

## API and contract

- \`encode_npm_generation(&generation, max_bytes)\` serializes a version-1 JSON object with \`version\`, source-bound \`checkpoint\` and \`snapshot\`. Serialization uses a bounded streaming JSON writer: bytes are rejected before extending the output beyond the caller's ceiling. The in-process publication sequence is **not** stored.
- \`restore_npm_generation(&store, bytes, &scope, expected_sequence, max_bytes, raw_limits, inventory_limits)\` rejects zero budget, oversized inputs, malformed/non-UTF8 JSON, duplicates at every JSON object depth, unexpected envelope fields or unsupported versions. It deserializes a typed bundle and calls \`NpmGenerationStore::publish\`, which independently checks the current tenant/source grants, source digests, complete recorded provenance, canonical inventory integrity and graph and performs the compare-and-swap generation swap.
- Imports are **not** permitted to bypass source reauthorization or immutable snapshot verification. If the current source files changed, return an error; no stale graph becomes authoritative.

## Adversarial and regression matrix

1. Deterministic export of one verified graph, stable JSON replay, exact-size boundary and one-byte-under budget rejection.
2. Import into an empty store; snapshot/checkpoint pair equality; publication sequence starts at 1; re-export equals original. Retained first-generation reader is unaffected by a permitted later swap.
3. A competing writer or stale \`expected_sequence\` never overwrites a current generation. Import failures never publish partial state.
4. Duplicate envelope and nested checkpoint keys, unexpected envelope fields, unsupported bundle version, binary garbage, truncated JSON, forged checkpoint fingerprint and unsupported snapshot schema fail closed.
5. Foreign tenant, revoked/ungranted manifest source and mutated lock content fail under live verification; restore is not equivalent to accepting saved SHA-256 alone.
6. Existing strict Linux quality/unit/integration/security/regression/packaging/RustSec/dependency/SemVer gates, Windows integration and Rust 1.85 MSRV must all pass on **the final PR head**, plus automated review findings.

## Deliberate limits

The format is an interchange/recovery *candidate*, **not** a durable crash-safe storage engine. It does not write to disk, rename files, implement fsync, manage leases, persist a monotonic publication counter, perform cross-restart anti-rollback, or coordinate source filesystem writers. A host must implement external crash-consistent publication and trusted anti-rollback state when required. An unkeyed checkpoint fingerprint is not authentication; access control and optional signing/encryption of stored bundles remain host-owned. The canonical snapshot may carry sensitive paths and other asset metadata and should be stored and transported accordingly.

The existing FOSS-322 dependency semantics remain conservative; optional/dev/peer/workspace/alias semantics, automated rescans and resumable parser orchestration remain out of scope. Parent FOSS-322 remains In Progress.
