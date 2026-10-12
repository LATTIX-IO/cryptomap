# FOSS-322.19 — Safe Cargo manifest package metadata profile

## Decision and boundary

Resume original FOSS-322 collector scope rather than expanding checkpoint storage. Earlier strict Cargo.toml parsing rejects common package metadata, making read-only dependency discovery fail even when direct dependency declarations are safe exact pins. This increment extends **only** the existing conservative Cargo manifest profile; it is not a full TOML parser, dependency solver, or Cargo build.

## Implementation and contract

Extend `crates/cryptomap/src/collectors/dependency/manifest.rs::parse_manifest` to accept optional keys inside a unique `[package]` section:

- `edition = "2015" | "2018" | "2021" | "2024"`
- `rust-version = "1.MINOR"` or `"1.MINOR.PATCH"`, where each numeric component is nonnegative canonical decimal with no leading zeros and no overflow
- `publish = true | false`, literal booleans only (never an implicit authorization or registry publishing operation)

Reject repeated keys, TOML escapes, inline comments, extra unknown metadata, arrays, targets, renamed/optional/dev/peer/workspace declarations, ranges or other unsupported dependency semantics. Continue to reject duplicate package sections, duplicate dependency keys, ambiguous lockfile candidates and incorrect locked root references.

Do not alter persisted canonical inventory identity, raw observation schemas, source-grant policies, registry normalization, edge proof matching, or replay/storage APIs. Package metadata never constitutes dependency or algorithm-use evidence.

## Unit, regression, security acceptance

1. A previously accepted strict Cargo manifest yields precisely the same proven direct dependency names and versions when `edition`, `rust-version`, or `publish` are added within this safe profile.
2. All four editions and supported Rust version forms plus both boolean values are accepted deterministically.
3. Invalid editions, wrong/quoted publish types, duplicate keys, numeric overflow, prerelease/range/leading-zero Rust requirements, inline comment tricks, unsupported arrays and additional sections fail closed. No partial direct dependency proof escapes.
4. Historical strict Cargo and npm fixture tests remain unchanged and pass; no package manager execution, network activity, source grant expansion or crypto-use inference occurs.
5. Exact final-head CI required: Linux rustfmt, locked workspace check, strict Clippy, workspace tests/docs/package/RustSec/dependency policy/SemVer, Windows and Rust 1.85; resolve all actionable review findings. Review-service quota is not approval.

## Dependency and exit

Initially developed as a separate stacked branch over FOSS-322.18 PR #37. After #37 merges, rebuild or rebase onto the exact new squash-main commit; verify only FOSS-322.19 code/tests/docs appear in the diff and rerun final-head gates before merge.

This is an incremental manifest compatibility expansion only. Broader TOML grammar, optional/dev/target/workspace/renamed dependency profiles, file mutation exclusion, and exact SDD-wide collector acceptance remain out of scope. Parent FOSS-322 stays In Progress.
