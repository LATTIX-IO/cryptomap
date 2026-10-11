# FOSS-322.3 — Exact-pinned Cargo direct dependency reconciliation

## Scope and trust boundary

This increment adds a narrow, typed proof gate on top of the merged Cargo.lock reader. Call `cryptomap::collectors::dependency::manifest::reconcile_cargo_direct(scope, manifest_item, lock_item, limits)`. The caller first grants BOTH exact files under the same `CollectionScope`, using `grant_file(RawSourceKind::Dependency, ...)`. No Cargo process, package script, remote registry, arbitrary local file, or network endpoint is accessed.

A successful `CargoDirectReconciliation` contains a verified root package name/version, sorted uniquely matched dependency names/versions, and SHA-256 fingerprints for the *two* source files. The API never returns raw registry/Git source URLs, credentials, or manifest bytes. It does not claim a package was loaded or an algorithm used.

## Precisely supported input profile

- Strict small Cargo.toml profile: exactly one `[package]` with quoted `name` and `version`, exactly one `[dependencies]` section with quoted `dep = "=X.Y.Z"` *exact pinned* versions.
- Cargo.lock v3/v4 from the prior bounded parser, now retaining its validated `dependencies = [ ... ]` references. The root package must have no registry/Git source and must match manifest name and version exactly.
- The lock must contain exactly one candidate at each manifest-pinned name/version. Root lock dependencies must contain exactly those direct references. A bare dependency name cannot be disambiguated when another locked version shares that name; an explicit `name version` reference can be matched.
- Other TOML tables/fields, workspace inheritance, optional/build/dev/target dependencies, renames, version ranges, inline tables, nontrivial quoting, ambiguous package sources, missing or extra root dependency references yield typed fail-closed errors. Unsupported valid Cargo.toml is **not** claimed complete.
- Two authorized files are read once each; the *combined* byte budget, parser field/record limits and maximum number of dependencies are enforced before exposing a result. Caller-controlled data is never included in error formatting.

## Integration status and deferred scope

This is a **non-mutating validation/read API** returning direct dependency evidence, not a second canonical inventory or automatically emitted `RelationshipKind::DependsOn` edges. The existing Cargo.lock collector continues emitting `RawFactKind::Dependency` through the shared pipeline. FOSS-322.4 must project proved links into the canonical relationship/evidence model and extend manifest support (prefer a maintained full TOML parser with exact Rust 1.85 + locked dependency review); npm package.json reconciliation and checkpoint semantics remain out of scope. Keep FOSS-322 In Progress.

## Verification

Unit tests: exact pin parsing, manifest grammar gates, malformed duplicates and optional/target/feature rejection, no-match and ambiguity, version drift and byte budgets. Integration: two real scoped file grants, deterministic result and source hashes, source credential redaction, no implicit root/path authority, out-of-budget grants, combined limit and unverified dependency denial.

Required merge gates: final-head formatting, locked check, strict Clippy, unit/integration/regression/security tests, rustdoc, cargo package, security advisory/dependency policy, semver checks, Windows and Rust 1.85, all PR review findings resolved. No green checks from an obsolete PR head count.
