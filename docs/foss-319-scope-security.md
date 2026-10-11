# FOSS-319: explicit collection scope and OS capability boundary

This module adds caller-approved collection scope to the FOSS-318 collector extension API.

## Trust boundary

- The **host** authorizes which exact source files, certificate-store names, telemetry streams, and TLS destinations may be used. A collector's `CollectorDescriptor` is descriptive and **never grants access**.
- Approved file sources use `FileRoot` and `AuthorizedFile`: absolute paths anchor at the filesystem volume root; relative paths anchor to an opened current-directory handle (not a reconstructed current-directory pathname). Each descendant component opens through no-follow handles. Relative paths are checked when granted and used, through `cap-std` / `cap-fs-ext` rooted handles. Parent components are opened without following symlinks, and the final file has `FollowSymlinks::No`. Absolute paths, `..`, wildcards, junction/symlink redirection, and root escapes are rejected.
- File reads have caller-provided hard byte budgets (up to 64 MiB). The final file is opened without following links and in Unix nonblocking mode; the opened handle must be a regular file within the budget. `open_read` returns an opaque bounded reader, not a raw File. The library returns a sanitized typed error without echoing untrusted paths or source contents. There is no recursive discovery, directory listing, script execution, or write interface.
- Approved `NetworkTarget` has an exact DNS name or IP literal, port, explicit optional SNI, and caller-pinned IP addresses. IP literals can only be pinned to that same address. DNS names **require** an approved IP set supplied by the host; the library does not resolve DNS. `AuthorizedEndpoint::connect` checks both IP and port before dialing with a bounded timeout. There are no redirects, wildcard hosts, implicit discovered ports, or CIDR sweeps.
- `CollectionScope::validate_request` and `collect_scoped` check that every requested item has been granted by the host. Collector options do not create grants. Logical certificate-store/telemetry grants only designate approved IDs; access permissions and actual collection remain the responsibility of their future FOSS-323/FOSS-326 implementations.

## Critical limitation: trusted in-process collectors

Capability handles are useful for *cooperative or trusted* plugins. They do **not** stop arbitrary Rust code running in the same process from calling `std::fs`, `std::net`, libc or FFI directly. Run untrusted third-party collectors in an **OS sandboxed process** with host-enforced filesystem/network policy and expose only carefully delegated capabilities across IPC. This crate does not claim to be a sandbox or a complete enterprise authorization engine. Mandatory host-authentication and RBAC/ABAC are outside FOSS-319.

## Example Rust usage

```rust
use cryptomap::{
    CollectionScopeId,
    raw::RawSourceKind,
    scope::CollectionScope,
    network_scope::NetworkTarget,
};
use std::net::{IpAddr, Ipv4Addr};

let mut grant = CollectionScope::new(CollectionScopeId::new("tenant-project")?);
grant.grant_file(RawSourceKind::Dependency, "project-lock", "./fixture", "Cargo.lock", 128 * 1024)?;
let bytes = grant.open_file(RawSourceKind::Dependency, "project-lock")?.read_bounded()?;
assert!(!bytes.is_empty());

// The host explicitly chooses the destination IP; no DNS occurs in cryptomap.
grant.grant_endpoint(NetworkTarget::new(
    "api.example.com", 443, Some("api.example.com"),
    [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
)?)?;
let authorized = grant.open_endpoint("api.example.com:443")?;
assert_eq!(authorized.approved_destinations().len(), 1);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The example uses documentation-only TEST-NET-1 address 192.0.2.1 and does not perform a connection.

## Run and verify

```sh
cargo test --test scope_authorization --locked
cargo test --workspace --all-features --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Negative tests cover traversal, wildcard/device paths, file size limits, external and internal symlinks on Unix, optional Windows symlink tests where OS permissions allow, duplicate/unauthorized network grants, IP and port substitution, lack of DNS pins, logical name matching and unapproved collector requests.

## Remaining stories

- FOSS-320: normalize raw observations into canonical evidence and verified snapshots.
- FOSS-322..326: actual reference collectors must use these read/connect handles and document platform-specific permission checks.
- FOSS-327/FOSS-328: checkpoint reauthorization and exact diagnostic/partial-coverage aggregation.
- Production isolation of adversarial third-party plugins must be implemented by their host OS sandbox—not by trusting an in-process Rust trait.

## FOSS-319 root and FIFO hardening

Absolute roots anchor to the OS filesystem root; relative roots anchor directly to an opened `.` directory handle, rather than `current_dir().join(requested)` (which can race with a rename and replacement). Both descend through no-follow directory handles instead of ambient full-path check/open sequences. `root_path()` is display-only, and remains relative for relative grants. Intermediate symlink components are refused.

Each file open rechecks relative paths and parents, requests no-follow plus Unix nonblocking behavior, verifies the opened file handle is a regular file, and caps bytes. The public AuthorizedReader does not expose the underlying file descriptor. Concurrent file content mutation remains possible; collectors requiring stable identity should hash the bounded read.

This capability API does not confine untrusted in-process plugins; the host must provide an OS sandbox for malicious third-party code. New tests cover symlinked ancestors, FIFO substitution and read limits.

A deterministic Unix test anchors a directory handle, renames its pathname, creates a replacement directory with the same name, then proves descent through the original handle reads the authorized file rather than the replacement. The full Linux/Windows/MSRV CI matrix remains the merge gate.
