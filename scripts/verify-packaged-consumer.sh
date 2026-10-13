#!/usr/bin/env bash
# Offline clean-room validation of the .crate archive, not the workspace source.
set -euo pipefail
cd "$(dirname "$0")/.."

count="$(find target/package -maxdepth 1 -type f -name 'cryptomap-*.crate' | wc -l)"
if [[ "$count" -ne 1 ]]; then
    echo "Expected exactly one cryptomap crate; run cargo package --package cryptomap --locked" >&2
    exit 1
fi
archive="$(find target/package -maxdepth 1 -type f -name 'cryptomap-*.crate' -print -quit)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/unpacked" "$scratch/consumer/src"
tar -xzf "$archive" -C "$scratch/unpacked"
package="$(find "$scratch/unpacked" -mindepth 1 -maxdepth 1 -type d -name 'cryptomap-*' -print -quit)"
test -n "$package"
for expected in \
    Cargo.toml \
    README.md \
    LICENSE-MIT \
    LICENSE-APACHE \
    examples/cargo_scoped_inventory.rs \
    examples/npm_scoped_inventory.rs \
    examples/rust_scoped_source.rs \
    examples/fixtures/source/crypto_calls.rs \
    examples/fixtures/npm/package.json \
    examples/fixtures/npm/package-lock.json \
    examples/collector_skeleton.rs \
    examples/fixtures/manifest.fixture \
    examples/fixtures/lock.fixture
do
    if [[ ! -f "$package/$expected" ]]; then
        echo "Missing packaged release artifact: $expected" >&2
        find "$package" -maxdepth 4 -type f -print >&2
        exit 1
    fi
done

# Compile a completely separate package against the published archive contents.
cat > "$scratch/consumer/Cargo.toml" <<EOF
[package]
name = "cryptomap-cleanroom-smoke"
version = "0.0.0"
edition = "2024"

[dependencies]
cryptomap = { path = "$package" }
EOF
cat > "$scratch/consumer/src/main.rs" <<'EOF'
use cryptomap::{AssetKind, IdentityContext, InventoryBuilder, InventoryLimits};
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = IdentityContext::new("cleanroom-consumer")?;
    let mut builder = InventoryBuilder::new();
    let id = builder.ingest_candidate(
        AssetKind::Library {
            ecosystem: "cargo".into(),
            name: "ring".into(),
            version: "0.17.12".into(),
        },
        &identity,
        BTreeMap::new(),
    )?;
    let snapshot = builder.finalize(InventoryLimits::default())?;
    snapshot.verify(InventoryLimits::default())?;
    assert!(snapshot.assets.contains_key(&id));
    Ok(())
}
EOF
# Generate the dependency source only from the REVIEWED workspace Cargo.lock.
# The subsequent external builds use an empty Cargo home with a single
# vendored registry source, not the CI runner's warmed cache or network.
mkdir -p "$scratch/cargo-home"
cargo vendor --locked --versioned-dirs "$scratch/vendor" > "$scratch/cargo-home/config.toml"
CARGO_HOME="$scratch/cargo-home" cargo generate-lockfile --offline \
    --manifest-path "$scratch/consumer/Cargo.toml"
CARGO_HOME="$scratch/cargo-home" cargo run --offline --locked \
    --manifest-path "$scratch/consumer/Cargo.toml" --bin cryptomap-cleanroom-smoke

# A custom collector is compiled as a THIRD-PARTY crate, not an in-tree
# example. This checks the public trait, request, sink and coverage contracts.
mkdir -p "$scratch/consumer/src/bin"
cp "$package/examples/collector_skeleton.rs" "$scratch/consumer/src/bin/custom_collector.rs"
CARGO_HOME="$scratch/cargo-home" cargo run --offline --locked \
    --manifest-path "$scratch/consumer/Cargo.toml" --bin custom_collector

# Exercise the packaged example on fixture bytes copied into explicitly
# approved source filenames. Cargo excludes nested Cargo.toml subpackages.
mkdir -p "$scratch/input"
cp "$package/examples/fixtures/manifest.fixture" "$scratch/input/Cargo.toml"
cp "$package/examples/fixtures/lock.fixture" "$scratch/input/Cargo.lock"
CARGO_HOME="$scratch/cargo-home" cargo run --offline --locked \
    --manifest-path "$package/Cargo.toml" \
    --example cargo_scoped_inventory -- \
    "$scratch/input" "2026-10-12T12:00:00Z" "packaged-scope" "packaged-run"

# Independently exercise the npm profile from the exact packaged crate.
# Filesystem reads are limited to two explicit source grants; no npm command
# or lifecycle script is run by the example.
mkdir -p "$scratch/npm-input"
cp "$package/examples/fixtures/npm/package.json" "$scratch/npm-input/package.json"
cp "$package/examples/fixtures/npm/package-lock.json" "$scratch/npm-input/package-lock.json"
CARGO_HOME="$scratch/cargo-home" cargo run --offline --locked \
    --manifest-path "$package/Cargo.toml" \
    --example npm_scoped_inventory -- \
    "$scratch/npm-input" "2026-10-12T12:00:00Z" "packaged-npm-scope" "packaged-npm-run"

# Exercise the opt-in AST parser from the *packaged* crate, not workspace
# sources, through one exact read-only file capability. No Cargo script from
# the analyzed source file is run, and unsupported syntax cannot mean no use.
mkdir -p "$scratch/rust-input"
cp "$package/examples/fixtures/source/crypto_calls.rs" "$scratch/rust-input/crypto_calls.rs"
CARGO_HOME="$scratch/cargo-home" cargo run --offline --locked \
    --manifest-path "$package/Cargo.toml" --features rust-source \
    --example rust_scoped_source -- \
    "$scratch/rust-input" "crypto_calls.rs" "2026-10-13T15:00:00Z" \
    "packaged-rust-tenant" "packaged-rust-run"
