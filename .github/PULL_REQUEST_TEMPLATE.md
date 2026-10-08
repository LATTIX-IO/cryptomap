## Summary

Describe the change and the problem it solves.

## Scope

- [ ] Change is focused and intentionally scoped.
- [ ] Public API changes are documented.
- [ ] Security implications have been considered.

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo check --workspace --all-targets --all-features`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo doc --workspace --all-features --no-deps`
- [ ] Supply-chain / SemVer checks pass where applicable.

## Compatibility

Describe any API, behavior, wire-format, storage-format, cryptographic, or interoperability impact.

## Security

Describe new trust boundaries, unsafe behavior, cryptographic changes, input-handling changes, or security-relevant dependencies. Write `None` if not applicable.
