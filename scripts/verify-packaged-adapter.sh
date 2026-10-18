#!/usr/bin/env bash
# FOSS-486: paired, locked, offline source-archive consumer verification.
# Never reads CurrentUser/My or LocalMachine/My in CI.
set -euo pipefail
cd "$(dirname "$0")/.."

version="$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')"
core="target/package/cryptomap-${version}.crate"
adapter="target/package/cryptomap-windows-store-${version}.crate"
test -f "$core" && test -f "$adapter"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/source" "$scratch/cargo-home" "$scratch/source/consumer/src"

# Inspect both archives BEFORE extraction, including physical tar boundaries,
# public-certificate fixture bytes, version, license and path-policy limits.
python3 scripts/release_evidence.py \
  --archive "$core" --commit "$(git rev-parse HEAD)" \
  --workspace-manifest Cargo.toml --lockfile Cargo.lock \
  --output "$scratch/core-inspection.json"
python3 scripts/verify_adapter_release.py inspect \
  --archive "$adapter" --commit "$(git rev-parse HEAD)" \
  --workspace-manifest Cargo.toml --lockfile Cargo.lock \
  --output "$scratch/adapter-inspection.json"

tar -xzf "$core" -C "$scratch/source"
tar -xzf "$adapter" -C "$scratch/source"

cat > "$scratch/source/Cargo.toml" <<EOF
[workspace]
members = ["cryptomap-${version}", "cryptomap-windows-store-${version}", "consumer"]
resolver = "3"

[patch.crates-io]
cryptomap = { path = "cryptomap-${version}" }
EOF

cat > "$scratch/source/consumer/Cargo.toml" <<EOF
[package]
name = "cryptomap-adapter-cleanroom"
version = "0.0.0"
edition = "2024"

[dependencies]
cryptomap = { path = "../cryptomap-${version}", features = ["certificate-store-grants"] }
cryptomap-windows-store = { path = "../cryptomap-windows-store-${version}" }
EOF

cat > "$scratch/source/consumer/src/main.rs" <<'RUST'
use cryptomap::{
    CollectionScopeId,
    certificate_store_scope::{CertificateStoreGrant, CertificateStoreLocation, CertificateStoreTarget},
    collectors::certificate_store::{PublicCertificateStoreBackend, StoreProviderError},
    scope::CollectionScope,
};
use cryptomap_windows_store::WindowsCertificateStoreBackend;

fn main() {
    let mut scope = CollectionScope::new(CollectionScopeId::new("packaged-adapter").unwrap());
    let user = CertificateStoreTarget::new(CertificateStoreLocation::CurrentUser, "My").unwrap();
    let machine = CertificateStoreTarget::new(CertificateStoreLocation::LocalMachine, "My").unwrap();
    scope.grant_certificate_store("granted", CertificateStoreGrant::new(user, 4, 256 * 1024).unwrap()).unwrap();
    assert!(WindowsCertificateStoreBackend::new(&scope, "not-granted").is_err());
    let backend = WindowsCertificateStoreBackend::new(&scope, "granted").unwrap();
    let mut forbidden_callback = |_: &[u8]| -> Result<(), StoreProviderError> {
        panic!("no actual store enumeration permitted by archive UAT")
    };
    assert_eq!(
        backend.visit(machine, &mut forbidden_callback),
        Err(StoreProviderError::PermissionDenied),
    );
    #[cfg(not(windows))]
    assert_eq!(
        backend.visit(user, &mut forbidden_callback),
        Err(StoreProviderError::Unsupported),
    );
    // On Windows, only the packaged crate's own native ephemeral-memory
    // test module is allowed to call a real CryptoAPI provider.
}
RUST

# Build an isolated, reviewed lockfile-compatible vendor source snapshot.
# Network is available only during cargo vendor preparation; all replay
# commands after this point use an empty CARGO_HOME and --offline.
cargo vendor --locked --versioned-dirs "$scratch/vendor" > "$scratch/cargo-home/config.toml"
cp Cargo.lock "$scratch/source/Cargo.lock"
export CARGO_HOME="$scratch/cargo-home"

# The synthetic third-party workspace introduces a consumer package absent
# from the canonical workspace lockfile. Re-resolve OFFLINE only from vendored
# reviewed versions, then check every package against the original lock.
# This does not grant permission to download/upgrade a dependency.
cargo generate-lockfile --manifest-path "$scratch/source/Cargo.toml" --offline
python3 - "Cargo.lock" "$scratch/source/Cargo.lock" <<'PY'
import sys
import tomllib
from pathlib import Path

def packages(path):
    with Path(path).open("rb") as file:
        data = tomllib.load(file)
    if data.get("version") != 4:
        raise SystemExit("Unsupported generated Cargo.lock format")
    rows = data.get("package")
    if not isinstance(rows, list):
        raise SystemExit("Missing dependency inventory")
    return rows

original = packages(sys.argv[1])
replayed = packages(sys.argv[2])
ident = lambda row: (row["name"], row["version"], row.get("source"), row.get("checksum"))
approved = {ident(p) for p in original}
if len(approved) != len(original):
    raise SystemExit("Duplicate reviewed package identities")
exceptions = {"cryptomap-adapter-cleanroom"}
unexpected = [
    p for p in replayed
    if p["name"] not in exceptions and ident(p) not in approved
]
if unexpected:
    raise SystemExit("Offline replay resolved an unreviewed dependency: " +
                     ", ".join(sorted({p["name"] for p in unexpected})))
if sum(p["name"] == "cryptomap-adapter-cleanroom" for p in replayed) != 1:
    raise SystemExit("Missing exactly one synthetic consumer package")
for root in ("cryptomap", "cryptomap-windows-store"):
    if sum(p["name"] == root and p["version"] == "0.1.1-alpha.1" for p in replayed) != 1:
        raise SystemExit("Unapproved source package identity: " + root)
print("Offline paired source lock includes only reviewed package identities")
PY

cargo check --manifest-path "$scratch/source/Cargo.toml" --workspace --all-targets --offline --locked
cargo run --manifest-path "$scratch/source/Cargo.toml" -p cryptomap-adapter-cleanroom --offline --locked
# These unit tests execute from the package archive, not workspace sources.
# On Windows, the native module creates only private, ephemeral MEMORY stores.
cargo test --manifest-path "$scratch/source/Cargo.toml" \
  -p cryptomap-windows-store --offline --locked
echo "FOSS-486 paired archive UAT passed on $(rustc --version)"
