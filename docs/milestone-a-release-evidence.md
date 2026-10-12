# Milestone A release evidence gate

## Purpose

Produce deterministic, inspectable **unsigned** evidence from the exact `.crate` archive built and clean-room-tested by CI. This strengthens the first alpha release candidate without enabling crates.io publication.

`scripts/release_evidence.py` runs after `cargo package` and the offline external-consumer smoke test. It inspects the tarball without extracting any archive members.

## Security and correctness acceptance

1. Fail closed for unsafe paths, absolute/traversal entries, links, duplicate file names, unexpected crate root/version, omitted required licenses or manifest/README, unexpected `publish` state, malformed commit ID and oversized file/member counts.
2. Reject packaged filenames likely to contain credentials, including `.env*`, private key suffixes, and entries in `.ssh`, `.git`, `target` and `__pycache__`. Filename checks are **not a content secret scanner**.
3. Emit sorted `cryptomap:release-evidence:v1` JSON with exact archive filename, SHA-256, crate version, CI commit identifier and per-file byte lengths; output is reproducible for identical archive bytes and commit.
4. Require an explicit `publish = false` in the *packaged* Cargo manifest. Enabling crates.io remains a separate human-authorized release PR and must coordinate any deliberate change to this pre-release guard.
5. Execute adversarial regression tests via Python's standard-library unittest runner before inspecting the real packaged archive.
6. Upload the evidence as a GitHub Actions artifact for reviewer retrieval and record the CI run + candidate source commit. It is not a signature, registry provenance attestation or supply-chain SBOM.

## Reproduce locally

From the repository root:

```bash
cargo package -p cryptomap --locked
python3 -m unittest discover -s scripts -p 'test_release_evidence.py' -v
python3 scripts/release_evidence.py \
  --archive target/package/cryptomap-0.1.0.crate \
  --commit "$(git rev-parse HEAD)" \
  --output target/release-evidence/cryptomap.json
```

CI selects the single actual `cryptomap-*.crate` archive rather than guessing a version.

## Limitations / subsequent increment

This is an *inspection ledger*, not SPDX/CycloneDX SBOM, SLSA or Sigstore provenance. Remaining Milestone A deliverables are genuine dependency SBOM and provenance generation, public API and compatibility conformance, registry ownership verification, protected credential validation, approved first-version release metadata, and post-publication fresh registry consumption. No credential/registry secrets are read by the gate. Maintain publication disabled until intentional approval.
