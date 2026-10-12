# FOSS-322.8 — npm path-scoped transitive dependency proof

## Scope and architectural constraint

This increment adds the opt-in, passive `resolve_npm_transitive(scope, manifest_item, lock_item, RawLimits)` API in `collectors::dependency::npm_transitive`. It produces a deterministic `NpmTransitiveProof` containing independently SHA-256-attested manifest/lock inputs, unique installed nodes keyed by exact npm lockfile path, and direct/indirect edge pairs keyed by those paths.

**It does not create canonical InventorySnapshot DependsOn edges.** The current canonical `AssetKind::Library` identity uses ecosystem/name/version and cannot safely distinguish two npm installations at different paths. Inventing transitive canonical edges before a path-scoped identity evolution would collapse nested installations, lose installation context and risk false provenance. FOSS-322.9 must introduce an explicit path-aware canonical schema/evidence migration if this graph is to become canonical.

## Supported resolution rules

The API reuses FOSS-322.6 exact-pin manifest-to-lock reconciliation, which requires independently host-authorized exact file grants. It reopens package-lock only by that exact grant and compares the SHA-256 to the previously reconciled lock digest, rejecting concurrent mutation. No code execution, npm process, network, implicit glob, package download, file traversal or runtime crypto-use inference.

Within strict npm v2/v3 packages tables, each installed node has an explicit unique `node_modules` path with validated npm scope/name/version; a nested path must have an installed parent path. For any dependency, resolution checks the requiring package's immediate `node_modules` candidate, then walks installed ancestry outward until root. Nearest installed match wins; its exact version must equal the pinned dependency version. Root dependencies are separately checked by the existing manifest-to-lock proof. All reachable nodes and edges are sorted; package names or versions **alone** never determine edge identity.

Explicitly unsupported and fail-closed: semver ranges, aliases, workspaces/links, dev/optional/peer/bundled dependencies, malformed classification flags, invalid path components and traversal, inconsistent installed names or versions, orphan/unreachable nodes, unresolved candidates, and cycles. Cycles are checked through bounded nonrecursive graph algorithms. There is no silent partial graph or false absence.

## Acceptance tests

- Unit: path normalization, escaped and noncanonical path denial, scoped names, nearest installed ancestor versus hoisted root.
- Filesystem integration: independently authorized manifests and locks, exact SHA-256 provenance, deterministic replay, path-distinct nested and hoisted versions, same name/version at different installation paths, four exact edges across two independent transitive branches.
- Security/regression: absent grants, duplicate source item, bounded file reads, aggregate byte budgets, package/edge limits, path traversal, missing parents, workspace records, version drift, peer/optional roles, unreferenced orphan, malicious duplicated JSON keys, malformed nested versions and a reachable cycle.
- Merge gates: final-head Linux locked format/check, Clippy -D warnings, tests, docs, packaged crate, RustSec and dependency policy, SemVer; Windows compatibility; Rust 1.85 MSRV; complete actionable review resolution.

## Intentionally deferred

Path-bearing canonical inventory identity and persisted transitive evidence, complete npm dependency grammar, common complex workspaces/aliases/optional resolution, Cargo workspace/dev/target syntax, other ecosystems, and incremental checkpoint/invalidation APIs remain in FOSS-322. Parent FOSS-322 remains In Progress.
