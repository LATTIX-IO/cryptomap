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
    examples/fixtures/cargo/Cargo.toml \
    examples/fixtures/cargo/Cargo.lock
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
cargo run --offline --manifest-path "$scratch/consumer/Cargo.toml"

# Exercise the real-file, scope-granted reference flow from archive contents.
cargo run --offline --manifest-path "$package/Cargo.toml" \
    --example cargo_scoped_inventory -- \
    "$package/examples/fixtures/cargo" "2026-10-12T12:00:00Z"
