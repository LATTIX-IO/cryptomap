# Changelog

All notable changes to this project will be documented in this file.

The project follows Semantic Versioning once its public API reaches a stable contract. Pre-1.0 releases may evolve more rapidly, with breaking changes documented here.

## [Unreleased]

**Milestone A candidate:** `0.1.1-alpha.1` (not yet published). The independent crates.io `cryptomap 0.1.0` index entry predates this build and cannot be overwritten; publisher ownership is not established by repository metadata.

### Added

- A packaged third-party custom collector compatibility smoke test with vendored, offline and locked dependencies.
- Explicit pre-1.0 schema/identity/source-evidence compatibility policy and collector author guide.

- Milestone A: source-granted Cargo inventory reference example with deterministic fixture, canonical snapshot verification and negative tests.
- Offline clean-room smoke testing against the actual packaged crate and a fresh external consumer.
- Explicit first-release authorization switch, embedded dual licenses, crate registry metadata and release-readiness documentation.
- Locked software SPDX SBOM validation and protected main-only Sigstore build/SBOM attestation workflow (separate from Cryptomap's future CBOM data format).
- Packaged read-only npm reference example, offline external consumer verification and frozen `asset:v2` identity test vectors.

### Changed

### Fixed

### Security
