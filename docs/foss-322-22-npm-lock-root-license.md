# FOSS-322.22 — Strict npm lock root license metadata

## Scope

Package-lock v2/v3 package root entries may legitimately include optional `license` string metadata, but the strict direct proof gate currently rejects any such field as an unsupported source. Permit that inert metadata without allowing it to influence dependency proof, asset identity, source grants or algorithm-use inference.

## Implementation

Modify `npm_manifest.rs::prove` and `npm.rs::parse_lock` within the `packages[""]` root object. The independent lock-only collector must reject malformed recognized license metadata rather than reporting clean coverage:

- Allow optional `license`, validated as a nonempty trimmed string with the existing bounded `string_field`/safe-text checks.
- Do not emit it as a cryptographic observation, authorize a new source, assert SPDX/compliance truth or compare it to `package.json` (which does not currently support full license semantics).
- Reject objects/arrays, booleans/null/numeric values, empty/whitespace-only, control characters, oversize strings, duplicate JSON keys and any unknown root fields. Source file SHA-256 continues to attest exact lock bytes.
- Reuse the existing `StrictJson` parser, lockfile v2/v3 consistency checks, exact pinned package resolution, canonical graph/source evidence, tenant and scope authorization.
- Do not execute npm scripts, fetch packages, follow ambient paths or infer actual cryptographic use.

## Test-driven acceptance

1. Unit: optional root license `MIT`, `Apache-2.0`, `UNLICENSED`, and compound strings retain the exact baseline direct package proof.
2. Security: duplicate license, malformed types, empty, whitespace, oversized field, and unknown script field fail closed; no partial proof escapes. Lock-only parsing rejects malformed license as `MalformedSource` or oversized license as `ResourceLimit`, before source facts are emitted.
3. Integration: host-granted npm package.json and package-lock v3 with root license produce identical path-scoped canonical transitive graph and valid immutable snapshot; revoked manifest grant rejects; malformed license source fails.
4. Historical Cargo/npm collectors and security suite remain passing.
5. Exact-final-head Linux rustfmt/locked check/Clippy -D warnings/workspace tests/docs/package/RustSec audit/deny/SemVer, Windows, Rust 1.85, independent code/security review and zero actionable threads required before merge.

## Explicit deferrals

Full npm license expressions or compliance interpretation, npm optional/dev/peer/workspace/alias/version-range semantics, complete Cargo metadata and version grammar, and remaining FOSS-322 collector requirements stay outside this increment. Parent FOSS-322 remains In Progress.
