# FOSS-322.16 — Bounded integrity framing for npm recovery candidates

## Requirement

Introduce a version-marked, exact-length integrity envelope on top of the verified JSON recovery bytes delivered by FOSS-322.13–15. Detection of transport truncation, extra bytes and accidental corruption occurs before JSON parsing, source reauthorization, independent host pin checks and atomic publication.

## Format and APIs

Frame bytes: 8-byte ASCII magic `CMNPGEN1`, unsigned big-endian 64-bit payload length, 32-byte raw SHA-256 of the JSON bytes, then exactly that many JSON bytes.

- `write_framed_npm_generation(generation, writer, max_payload_bytes)` runs existing bounded serialization then writes the framed bytes to caller-selected `Write`. The maximum is a **payload** limit; the wire frame adds 48 bytes. A failing writer may leave partial bytes; host owns temp files, sync and atomic rename.
- `read_framed_npm_generation(reader, max_payload_bytes)` reads a fixed 48-byte header, rejects unknown format or zero/oversized length before body allocation, reads exactly the declared bytes, checks SHA-256 and consumes a single extra byte to reject trailing content. A blocking host reader needs a host-controlled deadline.
- `restore_framed_npm_generation_pinned(store, reader, anchor, scope, expected_sequence, limits)` composes framing checks with existing strict JSON, host trusted anchor, live authorized source bytes and full evidence graph verification and generation CAS.

## Adversarial acceptance

1. Unit: exact limit roundtrip, below-limit rejection, zero budget, unknown format, declared zero length, huge length (without large allocation), every truncated prefix, tampered body/hash and trailing bytes.
2. Security: injected I/O read failures rejected and no partial bytes are returned; checksum is **not** authenticity and is not a substitute for host trust anchor or authorization.
3. Integration: real recovered canonical graph and checkpoint exactly match verified input; denied grants, corrupted hash and stale expected sequence never publish an incomplete generation.
4. Normal package presence does not imply cryptographic algorithm execution, no scripts or network calls and no implicit source enumeration.
5. Exact-head Linux fmt/check/strict Clippy/tests/docs/package/RustSec/deny/SemVer, Windows and Rust 1.85 plus reviewer findings required before merge.

## Explicit non-goals

This is a framed transport format, not a durable transaction log, cryptographic signature, MAC, encryption, source mutation lock, replay-resistant store or streaming JSON parser. Host-managed crash consistency, trusted anchor persistence, deadlines and broader npm/Cargo semantics are deferred. Keep FOSS-322 open pending complete original SDD coverage.
