# FOSS-322.14 — Host-pinned npm generation recovery

## Problem

FOSS-322.13 recovery reauthorizes both current source files and verifies the
source-bound checkpoint, graph and inventory. That is necessary but not sufficient
for rollback prevention. An attacker who reverts both package files and the saved
bundle can make a previously valid older generation pass integrity and source
checks. An unkeyed checkpoint SHA-256 is not anti-rollback protection.

## New optional API

\`NpmTrustedRecoveryAnchor::new(snapshot_id, checkpoint_fingerprint)\` validates
the syntax of a lower-case SHA-256 checkpoint fingerprint and binds a canonical
snapshot ID to that exact source-bound checkpoint. The anchor is **not**
serialized inside the untrusted recovery bundle and has no built-in file loading.

\`restore_npm_generation_pinned(store, bytes, trusted, scope, expected_sequence,
limits: NpmRecoveryLimits)\` first decodes the same strict,
versioned and byte-bounded JSON contract as FOSS-322.13. It rejects a bundle if
either its canonical snapshot identity, checkpoint snapshot identity or exact
checkpoint fingerprint differs from the independent trusted anchor. Only then
does it call the prior \`NpmGenerationStore::publish\`, which still checks
actual host-granted manifest/lock bytes, independently persisted collector
evidence, canonical graph and CAS publication.

The old \`restore_npm_generation\` remains available for consumers without a
rollback-resistant external trust anchor. It is not an anti-rollback API.

## Security boundary

The host must preserve the anchor's integrity and monotonicity independently
of the restore candidate. Protect it with trusted, rollback-resistant state,
hardware-backed policy, or a designated external authority. Merely saving the
anchor beside the candidate does **not** create security: an attacker who can
roll back both can defeat the pin. Matching a SHA-256 fingerprint does not
authenticate the issuer. The library does not invent a signing key or silently
authorize filesystem access.

## TDD acceptance

1. A correct trusted anchor permits bounded replay of an otherwise valid
   generation. The store owns the atomic publication sequence and does not
   mutate on any pin/authorization mismatch.
2. Invalid, uppercase, short or malformed checkpoint hashes fail during anchor
   construction; a syntactically valid wrong hash fails before publication.
3. Revoked manifest grants and a stale expected in-memory sequence fail closed.
4. Integration regression: generate two separate valid tenant/source-bound
   generations with different independently attested source digests. The old
   bundle still passes basic restore if the source files are reverted, but a
   trusted anchor pinned to the newer generation rejects it. The actual newer
   bundle passes pinned restore.
5. Exact-head Linux stable fmt/locked check/strict Clippy/unit/integration/
   regression/security tests/docs/package/RustSec/dependency policy/SemVer,
   Windows and Rust 1.85, and actionable reviewer findings must pass.

## Exclusions

No implicit external durable key store, host restart counter, disk writer,
filesystem watcher, rollback-resistant storage implementation, signed
attestation, optional dependency ecosystem expansion, or resumable scan
execution. Parent FOSS-322 remains In Progress.

## Branch and validation handoff

This increment is developed on its own feature branch and must remain unmerged while FOSS-322.13 PR #32 is open. After #32 is squash-merged, verify that this PR contains only the new trusted-anchor code, run the exact final-head matrix against the new main baseline, resolve review findings and only then merge. No trusted-anchor claims depend on an unprotected, in-process sequence counter.
