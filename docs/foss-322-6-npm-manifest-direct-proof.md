# FOSS-322.6 — Scoped npm package.json direct-dependency reconciliation

## Objective and API

The opt-in, read-only API `collectors::dependency::npm_manifest::reconcile_npm_direct(scope, manifest_item, lock_item, limits)` correlates a caller-granted package.json against a caller-granted package-lock.json v2/v3. The two exact source files must both have `RawSourceKind::Dependency` grants under the same administrative `CollectionScope`. No ambient filesystem access, npm CLI invocation, lifecycle hooks, package downloads or network calls occur.

A successful `NpmDirectReconciliation` returns the root name and version, lexically sorted direct dependency names/versions, and independent SHA-256 hashes of the two approved source files. It does not return registry URLs, npm credentials or raw JSON. The result is **declaration/resolution evidence**, not runtime use or a canonical dependency graph.

## Strict supported profile

- package.json is a JSON object with **only** `name`, `version` and `dependencies`. Root version and dependency pins use strict `MAJOR.MINOR.PATCH` unsigned numeric versions without prerelease, build metadata, leading-zero segments, ranges, aliases or workspace syntax. Scoped package names are allowed.
- package-lock.json has lockfileVersion 2 or 3, a `packages[""]` root record with matching name, version and exact `dependencies` map, and each direct package at exactly `node_modules/<name>` with the same version. Nested transitive packages are not projected into direct edges.
- The existing strict npm lockfile parser is reused for duplicate-key, path and package validation. Linked/workspace packages, partial lockfile coverage, malformed entries, unrecognized root or manifest semantics, missing root declarations and mismatched versions **fail closed**.
- For simplicity and correctness, common real-world package.json properties such as scripts, devDependencies, optionalDependencies, peerDependencies, overrides and workspaces are *not supported by this increment*. They are not executed or silently ignored.
- The combined byte budget for both files, per-file exact grants, string limits and package-count quotas are enforced before returning any result. Errors carry only sanitized variants and never input bytes or secret-bearing registry URLs.

## Verification and merge gate

Parser unit tests validate scoped exact matches, strict version/name syntax, duplicate JSON keys, root/installed drift, workspace/link and other unsupported features, and resource counts. End-to-end filesystem tests cover deterministic two-run proof, exact-grant denial, mismatched source identity, changed lock/manifests, no credential leakage, link/path injection, per-file read budgets, aggregate byte budgets, duplicate nested keys and optional/workspace omission hazards.

Merge only with exact final-head green Linux cargo fmt, locked workspace check, strict Clippy, unit/integration/regression/security tests, rustdoc, package, RustSec and dependency deny, SemVer checks, plus Windows and Rust 1.85 MSRV, and all actionable review findings resolved.

## Out of scope

This increment does **not** add an npm manifest collector, persisted dual-source npm evidence or canonical npm DependsOn projection. Those belong to FOSS-322.7. Supporting real npm manifest semantics beyond the strict profile, transitive edges and checkpoint/invalidations remain FOSS-322 follow-on work. Keep FOSS-322 In Progress.
