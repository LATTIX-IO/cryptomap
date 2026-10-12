# FOSS-322.17 — Capability-rooted immutable generation slots

## Objective

Allow a host to publish one fully serialized npm generation frame as an immutable, create-only file in a directory capability the host explicitly supplies. Prevent partial file contents being advertised under the published name; reject overwrites without using a platform-dependent rename/replace operation.

This follows FOSS-322.16 transport integrity framing and preserves source-bound, canonical graph and host-trusted anchor verification at recovery. It is not a repository scanner or an automatic persistent service.

## API contract

`publish_immutable_npm_generation_slot(dir, generation, staging_name, slot_name, max_payload_bytes)`

- `dir` is an already-open `cap_std::fs::Dir`; the library does not open ambient directories.
- `staging_name` and `slot_name` are distinct, nonempty ASCII basename tokens, 1–96 characters using only `[A-Za-z0-9_-]`. No dot components, delimiters, path traversal, absolute paths, symlinks or paths underneath nested directories are accepted.
- Full versioned frame encoding and byte budget validation happen **before** creating the staging file.
- Stage creation uses `create_new` and `FollowSymlinks::No`. The complete frame is written, the file is `sync_all`ed, and the writer is closed before the commit operation.
- `Dir::hard_link(staging, dir, slot)` creates the destination name only if it does not already exist. It does not overwrite any previous file or symlink. A cleanup guard best-effort unlinks the staging name on success or failure. A failed cleanup can leave an orphan staging file; it does not unpublish an existing destination.
- Return the framed byte count or a fail-closed error. Hosts must persist and synchronize their trusted checkpoint anchor separately.

## Security boundaries and known residual risks

The supplied directory **must be owned exclusively by the host**, not writable by untrusted users, because an attacker with write access can substitute the staging name between handle closure and hard-link creation. This library cannot repair that cross-process authorization deficiency. Host must also supply unique staging names; an existing staging slot fails closed rather than being replaced.

Hard links are not supported on every filesystem. Unsupported hard-link operations fail closed. A synced file alone does not imply a newly created directory entry has survived sudden power loss. Host-managed directory fsync/platform-specific durability, rollback-resistant pointer publication, stale-file cleanup, cross-process coordination and crash-recovery garbage collection are **not yet implemented**. A restored file is never trusted without independent source grants, strict framed decode, graph proof and host trust anchor.

The implementation does not execute package manager commands, download dependencies, follow ambient paths or infer actual cryptographic use from dependency presence.

## Test-driven acceptance matrix

1. **Unit**: basename length/alphabet restrictions; reject empty names, slash/backslash, dot, NUL, punctuation and duplicates.
2. **Integration**: bounded, exact framed generation is staged and published into a caller-granted temporary directory; staging entry is removed and the slot decodes back into the identical verified canonical snapshot/checkpoint.
3. **Regression**: repeated publication to the same slot cannot overwrite contents; preexisting unrelated slot remains untouched. Existing staged names fail closed.
4. **Security**: attempted traversal, aliased stage/destination, too-small payload budgets fail before creating a file. The underlying recovery verifier still enforces tenant/source grants and CAS.
5. **Merge gates**: exact-head Linux strict fmt/check/Clippy/tests/docs/package/RustSec/deny/SemVer; Windows locked compilation and integration; Rust 1.85; completed code/security review; zero actionable threads.

This is one bounded increment under FOSS-322, not full original SDD completion. Remaining work includes crash-consistent directory durability, external anchor monotonicity, resumable scan execution and broader Cargo/npm grammar and dependency profiles.
