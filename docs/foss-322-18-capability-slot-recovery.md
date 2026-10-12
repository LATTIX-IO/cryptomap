# FOSS-322.18 — Capability-scoped, pinned immutable-slot recovery

## Problem and dependency

FOSS-322.17 publishes a fully written, file-synced recovery frame under a create-only slot name within a host-supplied `cap_std::fs::Dir`. The existing verified recovery APIs accept a host-supplied reader, leaving each integration to implement safe slot opening. This increment closes that boundary without introducing ambient directory access or weakening the previously established tenant/source/grant/anchor protections.

Depends on merged #36 (FOSS-322.17). PR must be rebased as a direct child of the #36 squash commit before merge.

## Public API and constraints

`restore_immutable_npm_generation_slot(dir, slot_name, store, anchor, scope, expected_sequence, limits)`

- The caller supplies an **already-open** directory capability that it owns; the library does not open a host-selected string path, search directories or access network resources.
- Slot names must be nonempty ASCII-only basenames of 1–96 letters/digits/dash/underscore, exactly matching the create-only publishing contract.
- Use `cap_std::fs::Dir::open_with` with `OpenOptions::read(true)` and `FollowSymlinks::No`; validate the opened **handle** is a regular file. Reject missing/directory/symlink/reparse-point sources, not merely string traversal.
- Enforce a checked `max_payload_bytes + 48` (frame header) bound against the opened file's reported metadata *before* stream decoding; fail closed on overflow/zero budgets. Treat metadata as advisory: the frame decoder independently rejects changed, truncated, overlimit or trailing bytes after open.
- Pass the handle only to the FOSS-322.16 strict bounded frame decoder and FOSS-322.14 pinned recovery verifier, retaining independent host trust anchor, live exact-grant source reads, canonical graph and evidence verification, and generation compare-and-swap.
- Never overwrite, remove, discover, authenticate, or garbage-collect a slot as a side-effect of recovery.

## TDD acceptance

1. **Unit/security**: empty, dot, traversal, separators, invalid UTF/control and missing names fail before successful recovery; directories fail even when name passes.
2. **Integration**: publish via FOSS-322.17 into a caller-owned directory, reopen via the new API, and reconstruct exactly the same canonical snapshot, checkpoint and first-generation sequence.
3. **Authorization and regression**: revoked manifest grant and forged independently trusted anchor reject without changing current store; attempting initial recovery twice with stale CAS expectation also rejects.
4. **Filesystem security**: Unix symlink to an otherwise-valid recovery frame fails due no-follow; oversized file rejects before allocation and corruption fails while preserving previously published generation.
5. **Merge gates**: final-head Linux `cargo fmt --all -- --check`, locked check, strict Clippy -D warnings, unit/integration/regression/security tests, rustdoc, package, RustSec audit, deny and SemVer; Windows locked build/tests; Rust 1.85 locked check/tests; security review and all actionable review threads resolved.

## Explicit exclusions

The directory capability must be host-authorized and isolated from untrusted writers. A handle-bound read is not an immutable filesystem snapshot if another privileged host writer can mutate an inode concurrently; source mutation coordination, directory sync/power-loss durability, trusted anchor persistence and monotonicity, revocation of old on-disk slots, resumable collection and broader Cargo/npm semantics remain separate work. An unkeyed recovery frame digest is **not** authentication. FOSS-322 remains In Progress.
