# FOSS-322.15 — Explicit bounded npm generation recovery I/O

## Goal and dependency

FOSS-322.13 provides typed, strict JSON recovery bundles and FOSS-322.14 adds
host-supplied rollback-resistant identity checks. Neither module owns I/O.
This increment provides explicit, bounded adapters over caller-supplied Rust
\`Read\` and \`Write\` streams. A stream can be memory-backed, filesystem-backed
or custom: the library never opens a path, grants access, downloads packages or
automatically discovers sources.

## API

- \`read_bounded_npm_generation(reader, max_bytes)\` rejects zero/unrepresentable
  budgets, failed reads and payloads larger than the budget. Reads at most
  \`max_bytes + 1\` bytes, using one extra byte to detect oversized payloads.
  Returned bytes remain untrusted and are not decoded or published.
- \`write_bounded_npm_generation(generation, writer, max_bytes)\` first completes
  verified bundle encoding under the byte ceiling, *then* writes with
  \`write_all\`. Oversize encoding writes zero bytes. A failed sink may contain
  a partial candidate; the host must discard or atomically stage/rename it.
- \`restore_npm_generation_pinned_from_reader(store, reader, anchor, scope,
  expected_sequence, limits)\` composes bounded reads with strict envelope
  parsing, trusted anchor matching, live exact-grant source/evidence/graph
  revalidation, and prior atomic compare-and-swap publication. On any error,
  the previous generation is unchanged.

## Test-driven acceptance

1. Unit: exactly-at-cap read succeeds; one-byte-over-cap rejects after reading
   only \`max_bytes + 1\`; zero and unrepresentable caps reject without read.
   Injected \`Read\` errors reject without returning partial bytes.
2. Integration: encode generation into a caller-owned buffer; exact-bound
   output and input succeed with identical typed snapshot/checkpoint. Replaying
   at a stale expected generation rejects and preserves the live pair.
3. Security/regression: undersized encoder budget writes zero bytes; sink
   failing after partial writes propagates an error; truncated and oversized
   incoming streams cannot publish; revoked manifest grants are still denied.
4. No algorithm use is inferred from dependency presence, no dependency scripts
   execute, and no network or ambient directory traversal occurs.
5. Final-head Linux formatting, locked check, strict Clippy, tests,
   documentation/package, RustSec audit, cargo-deny and SemVer, plus Windows
   and Rust 1.85 jobs and actionable reviewer findings must pass.

## Non-goals and remaining risks

These are synchronous Rust trait adapters, not a durable checkpoint database.
No crash-consistent write, fsync, atomic replace, external trusted anchor store,
cross-restart monotonicity, streaming JSON parser, resumable collection, file
locks, source mutation exclusion, or deadline/cancellation is implied.
The host must enforce cancellation/timeout on blocking readers and protect
its output stream and trusted anchor. A caller that requests a very large
allowed byte budget is responsible for the associated memory allocation.

FOSS-322 remains In Progress for durable checkpoint lifecycle and broader
Cargo/npm dependency-profile semantics.
