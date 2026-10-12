# FOSS-322.9 — Canonical npm installation identity and evidence-backed transitive edges

## Design boundary and compatibility

This increment extends FOSS-322.8's conservative, path-unique npm graph proof into the existing canonical snapshot without changing schema version 2, the public AssetKind enum, or existing Library identities. It uses the already-supported `AssetKind::Extension { namespace: "cryptomap:npm-install", kind: "installed-dependency:v1" }`. The derived version-2 `AssetId` includes host-pinned tenant scope and a **typed JSON tuple** of protocol tag, exact lock source item, canonical `node_modules` installation path (or `npm:root`), package name and installed version via `IdentityContext.with_use_site`. Namespaced, secret-free extension metadata records path, package name/version, and source-item identifier. Two installations with identical name/version but different paths therefore retain independent canonical identities; existing Library assets and v2 snapshots continue to deserialize and maintain original identities. The extension is a new, opt-in semantic profile; consumers should understand its namespace before interpreting it.

## Canonical projection API

`project_npm_transitive_edges(snapshot, scope, manifest_item, lock_item, raw_limits, inventory_limits)` first revalidates the canonical snapshot and independently authorized file grants through the existing `project_npm_direct_edges` dual-source contract. It re-reads the files using FOSS-322.8 `resolve_npm_transitive`, then checks that the separately obtained manifest and lock SHA-256 fingerprints agree before creating any new asset or edge.

For **every** installed package, the collector must already have persisted `Direct/Confirmed` lockfile package-presence evidence from `cryptomap:npm-lockfile` version `0.2.0` in the same scoped, successful, complete run, with the current lockfile SHA-256 and exact deterministic source-path event (`npm:root` versus `node_modules/<path>`). For each projected edge, both endpoint observations must share a genuine lock collector run, and the canonical `DependsOn` references their existing evidence IDs. The independently collected npm manifest root/direct evidence remains mandatory through the existing direct projector. No evidence/run is synthesized. Original Library assets, raw observations and evidence remain untouched; legacy direct DependsOn relationships are preserved and the new relations connect only namespaced npm-install Extension assets.

All installed node and edge additions are computed and bounded first, then rebuilt through the canonical `InventoryBuilder`, finalized and independently verified for the caller's exact tenant scope. Failed projection returns no partial graph.

## Security invariants and acceptance tests

The source and transitive verifier rejects missing file grants, changed manifest/lockfile bytes, name/version or root-path mismatches, missing nested node evidence, source item/run/tenant substitution, unsupported npm dependency classifications, cycles, orphans, malformed paths, duplicate JSON, and budget exhaustion. There is no npm execution, lifecycle script execution, network access, arbitrary workspace traversal, inferred cryptographic algorithm use, or unverified source attribution.

Unit/integration/regression/security acceptance includes old Library identity compatibility; deterministic typed, path-specific identity; same-name/same-version nested collision defense; two separately collected source runs; persisted four-edge transitive projection plus original direct relationships; stable replay at exact asset/relationship limits; canonical JSON round-trip on schema 2; evidence provenance; missing and stale nested evidence; tenant and source-item isolation; credential non-disclosure and hard resource limits. Existing FOSS-322.8 path resolution tests remain green.

Merge gates: exact final-head Linux formatting, locked compilation, strict Clippy, all unit/integration/regression/security tests, documentation, packaging, RustSec/dependency policy, SemVer; Windows compatibility; Rust 1.85 MSRV; all actionable review threads resolved.

## Still out of scope

This is a conservative exact numeric production-dependency profile. Support for general npm semver ranges, workspaces, aliases, peer/optional/dev resolution, full Cargo TOML/workspace/target semantics, incremental checkpoint invalidation and end-to-end dependency collector release coverage remains open under FOSS-322. Parent issue stays In Progress.
