# cryptomap

Cryptographic asset discovery, inventory, and CBOM tooling.

Maintained by Lattix Technologies Corp.

Project website: https://lattix.io

## Status

This project is in early development.

Public APIs should be considered unstable until the relevant crates reach
their first stable release.

## Crates

- cryptomap

## Development

Run:

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace --all-features

## Publishing

All crates are bootstrapped with publish = false.

Before enabling publication for a crate:

1. Re-check the exact package name on crates.io.
2. Complete the public API and crate documentation.
3. Add tests for supported behavior.
4. Add crate-specific keywords/categories where appropriate.
5. Review dependency licenses and security posture.
6. Remove publish = false only for that crate.
7. Publish deliberately.

## License

Licensed under either:

- Apache License, Version 2.0
- MIT License

at your option.