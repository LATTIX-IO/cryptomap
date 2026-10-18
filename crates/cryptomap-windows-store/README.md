# cryptomap-windows-store — adapter release preview

Read-only, opt-in native Windows X.509 public certificate-store backend for
`cryptomap` (same exact workspace version). This companion crate does not
alter the pure-Rust cryptomap SDK's `forbid(unsafe_code)` boundary. It is not a
trust validator, certificate/key exporter, or certificate-discovery agent.

The adapter requires a typed host-created `CertificateStoreGrant` for exactly
one source item and never grants access itself. On non-Windows systems the
provider returns `StoreProviderError::Unsupported`. Win32 read-only access to
a physical registry store is available only after the host explicitly grants
`CurrentUser/My` or separately `LocalMachine/My`. CI tests ONLY ephemeral
in-memory native stores, never the real operating-system user or machine stores.

## Archive and distribution contract

Both `cryptomap` and this adapter remain `publish = false`. The adapter's
registry-style normalized `Cargo.toml` references an unpublished
`cryptomap` version. **The adapter .crate file cannot be independently
resolved from crates.io.** Consumers of this preview must receive both
matching, SHA-256-verified source archives and build them together, pinning
`cryptomap` to the local extracted source. An unpublished standalone registry
install is neither offered nor tested.

The package includes its own Apache-2.0/MIT license texts and two reviewed,
PUBLIC X.509 RSA/EC fixture certificates so the packaged native in-memory
test suite remains self-contained. Fixture DER SHA-256 hashes and archive
contents are checked during release inspection. No private keys are shipped.

## Qualification and local acceptance

Run from the repository root:

```sh
cargo test --locked -p cryptomap-windows-store
cargo package --locked -p cryptomap-windows-store --no-verify
bash scripts/verify-packaged-adapter.sh
python3 -m unittest discover -s scripts -p 'test_adapter_release.py' -v
```

The package smoke script vendor-pins the reviewed workspace Cargo.lock,
extracts both source archives into an isolated workspace, patches only the
local core path, runs a third-party consumer with no network, and executes
the adapter's own packaged tests. On Windows its tests instantiate ONLY
CryptoAPI memory stores; on Linux they verify explicit Unsupported semantics.

The operator-only native-store UAT is separately documented in
`docs/milestone-b5-windows-store.md`. It is **never** run by CI.

## Provenance limitations

A PR build generates unsigned inspection evidence, separate SPDX dependency
inventories and a combined core/adapter digest mapping. Only protected-main
workflow runs may sign SLSA and SPDX attestations for both tested archives and
the mapping; exact repo, workflow identity, ref and commit checks are required.
This does not authorize crates.io publication, code signing, or deployment.
