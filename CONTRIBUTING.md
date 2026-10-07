# Contributing

Contributions are accepted through GitHub pull requests.

## Development requirements

- Current stable Rust toolchain
- cargo fmt
- cargo check
- cargo clippy
- cargo test

Before submitting a pull request, run:

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace --all-features

Keep changes narrowly scoped.

Changes to public APIs must include corresponding documentation and tests.

Security-sensitive changes should describe the relevant threat model and security assumptions.