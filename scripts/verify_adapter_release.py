#!/usr/bin/env python3
"""FOSS-486: bounded inspection and exact locked provenance for an unpublished adapter.

These records are unsigned release inspection evidence. GitHub main-only
attestations (never this script) establish provenance after policy acceptance.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
import re
import tarfile
import tomllib
from pathlib import Path, PurePosixPath

from release_evidence import (
    MAX_ARCHIVE, MAX_ENTRIES, BAD_PARTS, BAD_SUFFIXES,
    BoundedDecompressedStream, audit_physical_tar_layout,
    expected_workspace_version, validate_public_certificate_fixture,
    PUBLIC_CERT_FIXTURE_SHA256, MAX_PUBLIC_CERT_FIXTURE_BYTES,
)

ADAPTER = "cryptomap-windows-store"
CORE = "cryptomap"
# Syft creates exactly one unversioned input-directory root when scanning the
# approved adapter manifest/lock snapshot. Its identity is deterministic for
# the configured scanner path and must never mask an unversioned extra package.
ADAPTER_SPDX_ROOT_NAME = "target/release-evidence/adapter-sbom-input"
ADAPTER_SPDX_ROOT_ID = (
    "SPDXRef-DocumentRoot-Directory-target-release-evidence-adapter-sbom-input"
)
EXPECTED_DIRECT = {CORE, "windows-sys", "x509-cert"}
# The source-packaged core in B5.3 intentionally builds without its optional
# parser/config features. This is an explicit, REVIEWED Cargo packaging profile,
# not a policy permitting arbitrary core-edge omissions. Requalify this constant
# and the archive tests whenever the core's default packaging features change.
PACKAGED_CORE_EDGES = frozenset({
    "cap-fs-ext", "cap-std", "const-oid", "serde",
    "serde_json", "sha2", "x509-cert",
})
# B5.5's opt-in HMAC feature activates the digest->subtle dependency in
# the REVIEWED workspace lock. The default-feature adapter .crate does not
# activate HMAC and Cargo legitimately omits precisely that edge. Do not
# weaken the graph checker to accept arbitrary transitive pruning.
PACKAGED_TRANSITIVE_PRUNING = {
    ("digest", "0.10.7"): frozenset({"subtle"}),
}
EXPECTED_FILES = {
    ".cargo_vcs_info.json", "Cargo.toml", "Cargo.toml.orig", "Cargo.lock",
    "README.md", "LICENSE-MIT", "LICENSE-APACHE",
    "src/lib.rs", "examples/read_user_store.rs",
    "examples/fixtures/certificate/rsa.pem",
    "examples/fixtures/certificate/ec.pem",
}
# Authenticated source bytes are compared to the reviewed checkout. Public
# PEM fixtures are verified separately by immutable SHA-256 pinned certificates,
# avoiding a second read of the same member from the non-seekable TAR stream.
# No arbitrary allowlisted code, docs, license, or sample may be signed as
# belonging to another commit, even when it passes self-modified tests.
SOURCE_FILES = EXPECTED_FILES - {
    ".cargo_vcs_info.json", "Cargo.toml", "Cargo.toml.orig", "Cargo.lock",
    "examples/fixtures/certificate/rsa.pem",
    "examples/fixtures/certificate/ec.pem",
}
ALLOWED_FILES = EXPECTED_FILES
ALLOWED_DIRS = {
    "/".join(path.split("/")[:index])
    for path in ALLOWED_FILES
    for index in range(1, len(path.split("/")))
}
CERT_PREFIX = "examples/fixtures/certificate/"
BAD_IDENTIFIERS = {"..", ".git", ".ssh", "target", ".env", "__pycache__"}
COMMIT = re.compile(r"[a-f0-9]{40}")
SPDX_CREATED = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
MANIFEST_SECTIONS = {
    "package", "lib", "example", "dependencies",
    "dev-dependencies", "target", "lints",
}


def _approved_dependency_contract(source: dict, version: str) -> tuple[dict, dict, dict, dict]:
    """Derive exact normalized dependency tables from reviewed local source."""
    package = source.get("package", {})
    if package.get("name") != ADAPTER:
        raise ValueError("invalid approved adapter source manifest")
    direct = source.get("dependencies", {})
    if set(direct) != {CORE} or not isinstance(direct[CORE], dict):
        raise ValueError("approved adapter source dependencies changed")
    core = direct[CORE]
    if core.get("path") != "../cryptomap" or core.get("version") != version:
        raise ValueError("approved local core path or version changed")
    expected_direct = {CORE: {key: value for key, value in core.items() if key != "path"}}
    return (expected_direct,
            source.get("dev-dependencies", {}),
            source.get("target", {}),
            source.get("lints", {}))




def digest(path: Path, maximum: int = MAX_ARCHIVE) -> str:
    if not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError("missing or oversized input")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _locked_packages(path: Path, version: str) -> tuple[dict, dict[str, str]]:
    if not path.is_file() or not 0 < path.stat().st_size <= 8 * 1024 * 1024:
        raise ValueError("missing or oversized Cargo.lock")
    with path.open("rb") as stream:
        root = tomllib.load(stream)
    if root.get("version") != 4 or not isinstance(root.get("package"), list):
        raise ValueError("unsupported Cargo.lock")
    packages = root["package"]
    selected = [p for p in packages if p.get("name") == ADAPTER and p.get("version") == version]
    if len(selected) != 1:
        raise ValueError("adapter root/version absent or ambiguous")
    dependencies = selected[0].get("dependencies", [])
    if not isinstance(dependencies, list) or not all(isinstance(d, str) for d in dependencies):
        raise ValueError("invalid adapter lock dependencies")
    direct = {}
    for entry in dependencies:
        parts = entry.split()
        if not 1 <= len(parts) <= 2 or parts[0] in direct:
            raise ValueError("ambiguous direct dependency")
        direct[parts[0]] = parts[1] if len(parts) == 2 else None
    if set(direct) != EXPECTED_DIRECT:
        raise ValueError("adapter dependency policy changed")
    resolved = {}
    for name, pinned in direct.items():
        versions = [p["version"] for p in packages if p.get("name") == name]
        valid = [v for v in versions if pinned is None or v == pinned]
        if len(valid) != 1 or len(versions) != len(set(versions)):
            raise ValueError("missing or ambiguous locked direct dependency")
        resolved[name] = valid[0]
    if resolved[CORE] != version or resolved["windows-sys"] != "0.61.2":
        raise ValueError("adapter/core compatibility or Windows target pin mismatch")
    return root, resolved


def _dependency_graph(packages: list, *, origin: str) -> dict:
    """Load a unique package identity -> sorted dependency-edge mapping.

    The packaged adapter's direct edge set is required to match EXACTLY.
    The adapter root and every resolved transitive edge are checked against
    the reviewed lock. The only authorized feature pruning is the explicitly
    pinned core package profile; arbitrary omissions are forbidden.
    """
    result = {}
    for row in packages:
        if not isinstance(row, dict):
            raise ValueError(f"malformed {origin} Cargo.lock entry")
        ident = (row.get("name"), row.get("version"), row.get("source"), row.get("checksum"))
        if (not isinstance(ident[0], str) or not ident[0]
                or not isinstance(ident[1], str) or not ident[1]
                or ident in result):
            raise ValueError(f"missing or duplicated {origin} package identity")
        edges = row.get("dependencies", [])
        if (not isinstance(edges, list)
                or not all(isinstance(x, str) and x.strip() for x in edges)
                or len(edges) != len(set(edges))):
            raise ValueError(f"invalid/duplicate {origin} dependency reference")
        result[ident] = tuple(sorted(edges))
    return result


def _check_closed_dependency_graph(graph: dict, version: str) -> None:
    """Require one complete, unambiguous transitive closure from adapter root."""
    roots = [identity for identity in graph
             if identity[0] == ADAPTER and identity[1] == version]
    if len(roots) != 1:
        raise ValueError("missing or ambiguous adapter dependency graph root")
    visited = set()
    pending = roots
    while pending:
        identity = pending.pop()
        if identity in visited:
            continue
        visited.add(identity)
        for reference in graph[identity]:
            parts = reference.split()
            if len(parts) not in (1, 2):
                raise ValueError("invalid dependency reference in packaged lock")
            matches = [
                candidate for candidate in graph
                if candidate[0] == parts[0]
                and (len(parts) == 1 or candidate[1] == parts[1])
            ]
            if len(matches) != 1:
                raise ValueError("missing or ambiguous packaged transitive dependency")
            pending.append(matches[0])
    if visited != graph.keys():
        raise ValueError("packaged dependency graph includes orphaned packages")

def inspect_adapter(archive: Path, lockfile: Path, workspace: Path, commit: str) -> dict:
    if not COMMIT.fullmatch(commit):
        raise ValueError("invalid source revision")
    version = expected_workspace_version(workspace, lockfile)
    _lock, dependencies = _locked_packages(lockfile, version)
    archive_digest = digest(archive)
    if archive.name != f"{ADAPTER}-{version}.crate":
        raise ValueError("adapter archive name/version mismatch")
    expected_root = f"{ADAPTER}-{version}"
    entries = set()
    regular_files = set()
    total = count = 0
    manifest = None
    original_manifest = None
    packaged_lock = None
    vcs_info = None
    checked_source_files = set()
    source_root = Path(__file__).resolve().parents[1] / "crates" / ADAPTER
    with archive.open("rb") as raw, gzip.GzipFile(fileobj=raw) as unzip:
        stream = BoundedDecompressedStream(unzip, MAX_ARCHIVE + MAX_ENTRIES * 2048 + 2 * 1024 * 1024)
        with tarfile.open(fileobj=stream, mode="r|") as tar:
            for member in tar:
                count += 1
                if count > MAX_ENTRIES:
                    raise ValueError("adapter archive entry ceiling exceeded")
                path = PurePosixPath(member.name)
                if (path.is_absolute() or len(path.parts) < 2
                        or path.parts[0] != expected_root or path.as_posix() != member.name.rstrip("/")
                        or any(x in BAD_IDENTIFIERS or x.startswith(".env") for x in path.parts)
                        or not (member.isfile() or member.isdir())
                        or member.issym() or member.islnk()):
                    raise ValueError("unsafe adapter archive path/type")
                rel = "/".join(path.parts[1:])
                if rel in entries or any(
                    "/".join(path.parts[1:position]) in regular_files
                    for position in range(2, len(path.parts))
                ):
                    raise ValueError("duplicate or overlapping adapter archive entry")
                if member.isfile() and rel not in ALLOWED_FILES:
                    raise ValueError("unapproved adapter file")
                if member.isdir() and rel not in ALLOWED_DIRS:
                    raise ValueError("unapproved adapter archive directory")
                if member.isfile() and any(prior.startswith(rel + "/") for prior in entries):
                    raise ValueError("adapter file shadows directory")
                entries.add(rel)
                if member.size > MAX_ARCHIVE:
                    raise ValueError("oversized adapter member")
                if member.isfile():
                    regular_files.add(rel)
                    total += member.size
                    if total > MAX_ARCHIVE:
                        raise ValueError("expanded adapter archive ceiling exceeded")
                    suffix = path.suffix.lower()
                    if suffix in BAD_SUFFIXES:
                        if suffix != ".pem" or not rel.startswith(CERT_PREFIX):
                            raise ValueError("secret-bearing adapter file")
                        original = rel.removeprefix(CERT_PREFIX)
                        digest_name = "examples/fixtures/certificate/" + original
                        expected = PUBLIC_CERT_FIXTURE_SHA256.get(digest_name)
                        if expected is None or member.size > MAX_PUBLIC_CERT_FIXTURE_BYTES:
                            raise ValueError("unreviewed public adapter cert fixture")
                        source = tar.extractfile(member)
                        if source is None:
                            raise ValueError("fixture inaccessible")
                        validate_public_certificate_fixture(
                            source.read(MAX_PUBLIC_CERT_FIXTURE_BYTES + 1), expected
                        )
                    if rel in SOURCE_FILES:
                        source = source_root.joinpath(*rel.split("/"))
                        if (not source.is_file() or source.is_symlink()
                                or not 0 <= source.stat().st_size <= MAX_ARCHIVE
                                or source.stat().st_size != member.size):
                            raise ValueError("missing or size-drifted reviewed adapter source")
                        handle = tar.extractfile(member)
                        if handle is None:
                            raise ValueError("unreadable adapter source archive member")
                        packaged_bytes = handle.read(member.size + 1)
                        if (len(packaged_bytes) != member.size
                                or hashlib.sha256(packaged_bytes).digest()
                                != hashlib.sha256(source.read_bytes()).digest()):
                            raise ValueError("packaged source differs from exact reviewed checkout")
                        checked_source_files.add(rel)
                    if rel == ".cargo_vcs_info.json":
                        if member.size > 4096:
                            raise ValueError("oversized Cargo VCS provenance")
                        handle = tar.extractfile(member)
                        if handle is None:
                            raise ValueError("unreadable Cargo VCS provenance")
                        try:
                            vcs_info = json.loads(handle.read(member.size + 1))
                        except (ValueError, UnicodeDecodeError) as exc:
                            raise ValueError("invalid Cargo VCS provenance") from exc
                        if vcs_info != {
                            "git": {"sha1": commit},
                            "path_in_vcs": "crates/cryptomap-windows-store",
                        }:
                            raise ValueError("packaged Git provenance does not match tested commit")
                    if rel == "Cargo.lock":
                        if member.size > 8 * 1024 * 1024:
                            raise ValueError("oversized packaged adapter lock")
                        source = tar.extractfile(member)
                        if source is None:
                            raise ValueError("unreadable adapter lockfile")
                        packaged_lock = tomllib.loads(source.read().decode("utf-8"))
                    if rel == "Cargo.toml.orig":
                        if member.size > 100_000:
                            raise ValueError("oversized original adapter manifest")
                        source = tar.extractfile(member)
                        if source is None:
                            raise ValueError("unreadable original adapter manifest")
                        original_manifest = source.read()
                    if rel == "Cargo.toml":
                        if member.size > 100_000:
                            raise ValueError("oversized adapter manifest")
                        source = tar.extractfile(member)
                        if source is None:
                            raise ValueError("missing adapter manifest")
                        manifest = tomllib.loads(source.read().decode("utf-8"))
    if count == 0:
        raise ValueError("empty adapter archive")
    audit_physical_tar_layout(archive, count)
    if (not EXPECTED_FILES <= regular_files or manifest is None
            or original_manifest is None or packaged_lock is None
            or vcs_info is None or checked_source_files != SOURCE_FILES):
        raise ValueError("adapter archive lacks authenticated source or metadata")
    trusted_source = (Path(__file__).resolve().parents[1] / "crates"
                      / ADAPTER / "Cargo.toml")
    if not trusted_source.is_file() or not 0 < trusted_source.stat().st_size <= 100_000:
        raise ValueError("reviewed adapter source manifest unavailable")
    approved_bytes = trusted_source.read_bytes()
    if original_manifest != approved_bytes:
        raise ValueError("packaged original Cargo.toml differs from reviewed source")
    reviewed_manifest = tomllib.loads(approved_bytes.decode("utf-8"))
    direct, development, targets, lints = _approved_dependency_contract(
        reviewed_manifest, version
    )
    if (set(manifest) != MANIFEST_SECTIONS
            or manifest.get("dependencies") != direct
            or manifest.get("dev-dependencies") != development
            or manifest.get("target") != targets
            or manifest.get("lints") != lints
            or manifest.get("lib") != {
                "name": "cryptomap_windows_store", "path": "src/lib.rs"
            }
            or manifest.get("example") != [{
                "name": "read_user_store", "path": "examples/read_user_store.rs"
            }]
            or manifest.get("package", {}).get("build") is not False):
        raise ValueError("normalized adapter dependency/build contract changed")
    if packaged_lock.get("version") != 4 or not isinstance(packaged_lock.get("package"), list):
        raise ValueError("invalid packaged adapter lockfile")
    reviewed_lock, _ = _locked_packages(lockfile, version)
    reviewed_graph = _dependency_graph(reviewed_lock["package"], origin="reviewed")
    selected = packaged_lock["package"]
    packaged_graph = _dependency_graph(selected, origin="packaged")
    if not packaged_graph or not packaged_graph.keys() <= reviewed_graph.keys():
        raise ValueError("packaged adapter lock has unreviewed package identities")
    for identity, edges in packaged_graph.items():
        baseline = reviewed_graph[identity]
        if identity[0] == CORE:
            # Cargo's reviewed source-package profile omits optional parser
            # features, but MUST retain these exact mandatory dependencies.
            # Do not accept arbitrary subsets as "feature pruning".
            if (set(edges) != PACKAGED_CORE_EDGES
                    or not set(edges) <= set(baseline)):
                raise ValueError("packaged core dependency profile changed")
        elif (identity[0], identity[1]) in PACKAGED_TRANSITIVE_PRUNING:
            # One explicitly pinned Cargo feature resolution, not a wildcard
            # exception permitting loss of dependency edges.
            removed = PACKAGED_TRANSITIVE_PRUNING[(identity[0], identity[1])]
            if not removed <= set(baseline) or edges != tuple(sorted(set(baseline) - removed)):
                raise ValueError("packaged transitive feature-pruning profile changed")
        elif edges != baseline:
            # All other transitive edges are exact; missing or redirected
            # packages fail closure and SPDX completeness checks.
            raise ValueError("packaged dependency graph lost or rewired edges")
    _check_closed_dependency_graph(packaged_graph, version)
    if any(
        sum(row.get("name") == name and row.get("version") == version for row in selected) != 1
        for name in (CORE, ADAPTER)
    ):
        raise ValueError("packaged adapter lock has mismatched root crates")
    pkg = manifest.get("package", {})
    if (pkg.get("name") != ADAPTER or pkg.get("version") != version
            or pkg.get("publish") is not False
            or pkg.get("edition") != "2024" or pkg.get("rust-version") != "1.85"
            or pkg.get("license") != "MIT OR Apache-2.0"):
        raise ValueError("adapter package identity / nonpublication failed")
    dep = manifest.get("dependencies", {}).get(CORE, {})
    win = manifest.get("target", {}).get("cfg(windows)", {}).get("dependencies", {}).get("windows-sys", {})
    if (not isinstance(dep, dict) or dep.get("version") != version
            or not isinstance(win, dict) or win.get("version") != "=0.61.2"):
        raise ValueError("adapter package dependency targets/version mismatched")
    # A normalized .crate with a registry-version dependency must NOT be
    # represented as independently installable until that version is published.
    return {
        "schema": "cryptomap:adapter-release-evidence:v1",
        "commit": commit, "crate": ADAPTER, "version": version,
        "archive": archive.name, "sha256": archive_digest,
        "dependencies": dependencies, "entry_count": count,
        "files": sorted(entries), "publish_enabled": False,
        # Preserve a canonical expected SPDX inventory derived from the
        # validated archive, not from unrelated workspace-only dependencies.
        "locked_package_versions": sorted(
            [{"name": identity[0], "version": identity[1]}
             for identity in packaged_graph],
            key=lambda item: (item["name"], item["version"]),
        ),
        "registry_resolvable": False,
        "limitations": ["unsigned", "path-paired source distribution only",
                        "not a crates.io install or code-signing authority"],
    }


def validate_adapter_spdx(path: Path, lockfile: Path, version: str,
                          expected_packages: list[dict]) -> dict:
    _locked, expected = _locked_packages(lockfile, version)
    if not path.is_file() or not 0 < path.stat().st_size <= 16 * 1024 * 1024:
        raise ValueError("missing or oversized adapter SPDX")
    doc = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(doc, dict) or doc.get("spdxVersion") != "SPDX-2.3"
            or doc.get("SPDXID") != "SPDXRef-DOCUMENT"
            or doc.get("dataLicense") != "CC0-1.0"
            or not isinstance(doc.get("name"), str)
            or not isinstance(doc.get("documentNamespace"), str)):
        raise ValueError("invalid SPDX document")
    info = doc.get("creationInfo", {})
    if (not isinstance(info, dict)
            or not SPDX_CREATED.fullmatch(info.get("created", ""))
            or not isinstance(info.get("creators"), list)
            or not info["creators"]):
        raise ValueError("missing SPDX creation metadata")
    entries = doc.get("packages")
    if not isinstance(entries, list) or not entries:
        raise ValueError("empty adapter dependency SPDX")
    found = set()
    ids = set()
    root_count = 0
    reported_inventory = Counter()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("invalid SPDX package record")
        identifier = item.get("SPDXID")
        if (not isinstance(identifier, str) or not identifier.startswith("SPDXRef-")
                or identifier in ids or not isinstance(item.get("name"), str)
                or not isinstance(item.get("downloadLocation"), str)):
            raise ValueError("duplicate or incomplete SPDX package")
        ids.add(identifier)
        name, actual = item["name"], item.get("versionInfo")
        if actual is None:
            # A NULL/omitted version is valid only for Syft's one input-root
            # directory. No other unversioned SPDX package is permitted.
            if ("versionInfo" in item
                    or name != ADAPTER_SPDX_ROOT_NAME
                    or identifier != ADAPTER_SPDX_ROOT_ID
                    or item.get("primaryPackagePurpose") != "FILE"
                    or item.get("filesAnalyzed") is not False
                    or item.get("downloadLocation") != "NOASSERTION"):
                raise ValueError("unapproved unversioned adapter SPDX package")
            root_count += 1
            continue
        if not isinstance(actual, str) or not actual.strip():
            raise ValueError("missing or malformed versioned SPDX package identity")
        reported_inventory[(name, actual)] += 1
        if name in expected:
            if actual == expected[name]:
                found.add(name)
            elif not any(
                p.get("name") == name and p.get("version") == actual
                for p in _locked["package"]
            ):
                raise ValueError("unlocked direct dependency version in SPDX")
    if found != EXPECTED_DIRECT:
        raise ValueError("adapter direct dependency coverage incomplete")
    if root_count != 1:
        raise ValueError("missing or duplicated Syft adapter input-directory root")
    if not isinstance(expected_packages, list) or not expected_packages:
        raise ValueError("missing validated adapter lock inventory")
    expected_inventory = Counter(
        (row["name"], row["version"]) for row in expected_packages
    )
    if len(expected_inventory) != len(expected_packages):
        raise ValueError("duplicate identity in expected packaged lock inventory")
    # Every other package MUST be versioned and exactly represented by the
    # validated archive-owned Cargo.lock (name, version and multiplicity).
    # Syft's single known directory root has already been checked separately.
    if reported_inventory != expected_inventory:
        raise ValueError("SPDX does not enumerate exact packaged dependency closure")
    return {
        "sha256": digest(path, 16 * 1024 * 1024),
        "direct_dependencies": expected,
        "package_count": len(entries),
    }


def aggregate(core: Path, adapter: Path, core_evidence: Path, adapter_evidence: Path,
              core_sbom: Path, adapter_sbom: Path, lockfile: Path,
              workspace: Path, commit: str) -> dict:
    version = expected_workspace_version(workspace, lockfile)
    if not COMMIT.fullmatch(commit):
        raise ValueError("invalid source commit")
    inspection = inspect_adapter(adapter, lockfile, workspace, commit)
    core_info = json.loads(core_evidence.read_text(encoding="utf-8"))
    adapter_info = json.loads(adapter_evidence.read_text(encoding="utf-8"))
    if (core_info.get("schema") != "cryptomap:release-evidence:v1"
            or core_info.get("commit") != commit
            or core_info.get("crate") != CORE or core_info.get("version") != version
            or core_info.get("sha256") != digest(core)
            or core_info.get("archive") != core.name):
        raise ValueError("core inspection / archive mismatch")
    if adapter_info != inspection:
        raise ValueError("adapter inspection / archive mismatch")
    from verify_release_sbom import validate as validate_core_spdx
    core_spdx = validate_core_spdx(core_sbom, lockfile)
    adapter_spdx = validate_adapter_spdx(
        adapter_sbom, lockfile, version, inspection["locked_package_versions"]
    )
    if core_sbom.resolve() == adapter_sbom.resolve() or core == adapter:
        raise ValueError("core and adapter artifacts must be separate")
    # Distinct subject digests and content paths bind the two SPDX reports to
    # different upstream archives. The root dependency contract is also checked.
    if digest(core_sbom, 16 * 1024 * 1024) == adapter_spdx["sha256"]:
        raise ValueError("reused SPDX as a different crate")
    return {
        "schema": "cryptomap:paired-release-v1",
        "commit": commit, "version": version, "publish_enabled": False,
        "source_distribution_only": True,
        "core": {"archive": core.name, "sha256": digest(core),
                 "sbom": core_sbom.name, "sbom_sha256": digest(core_sbom, 16 * 1024 * 1024),
                 "direct_dependencies": core_spdx["direct_dependency_versions"]},
        "adapter": {"archive": adapter.name, "sha256": digest(adapter),
                    "sbom": adapter_sbom.name, "sbom_sha256": adapter_spdx["sha256"],
                    "direct_dependencies": adapter_spdx["direct_dependencies"]},
        "dependency_edge": {
            "from": f"{ADAPTER}@{version}", "to": f"{CORE}@{version}",
            "mode": "offline-local-source-pair",
        },
    }


def verify_mapping(mapping: dict, core: Path, adapter: Path,
                   core_sbom: Path, adapter_sbom: Path, commit: str) -> None:
    if (mapping.get("schema") != "cryptomap:paired-release-v1"
            or mapping.get("commit") != commit or not COMMIT.fullmatch(commit)
            or mapping.get("publish_enabled") is not False
            or mapping.get("source_distribution_only") is not True):
        raise ValueError("mapping identity/ref mismatch")
    version = mapping.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+[-A-Za-z0-9.]*", version):
        raise ValueError("invalid mapped version")
    for member, archive, sbom in (("core", core, core_sbom), ("adapter", adapter, adapter_sbom)):
        expected = mapping.get(member, {})
        wanted = CORE if member == "core" else ADAPTER
        if (not isinstance(expected, dict)
                or archive.name != f"{wanted}-{version}.crate"
                or expected.get("archive") != archive.name
                or expected.get("sha256") != digest(archive)
                or expected.get("sbom") != sbom.name
                or expected.get("sbom_sha256") != digest(sbom, 16 * 1024 * 1024)):
            raise ValueError("mapping digest or subject mismatch")
    if mapping.get("dependency_edge") != {
        "from": f"{ADAPTER}@{version}", "to": f"{CORE}@{version}",
        "mode": "offline-local-source-pair",
    }:
        raise ValueError("invalid paired source dependency edge")
    expected = mapping.get("adapter", {}).get("direct_dependencies", {})
    if not isinstance(expected, dict) or expected.get(CORE) != version or expected.get("windows-sys") != "0.61.2":
        raise ValueError("version/window dependency mismatch")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    i = sub.add_parser("inspect")
    i.add_argument("--archive", required=True, type=Path)
    i.add_argument("--workspace-manifest", required=True, type=Path)
    i.add_argument("--lockfile", required=True, type=Path)
    i.add_argument("--commit", required=True)
    i.add_argument("--output", required=True, type=Path)
    a = sub.add_parser("aggregate")
    for arg in ["core-archive", "adapter-archive", "core-evidence",
                "adapter-evidence", "core-sbom", "adapter-sbom",
                "lockfile", "workspace-manifest"]:
        a.add_argument("--" + arg, required=True, type=Path)
    a.add_argument("--commit", required=True)
    a.add_argument("--output", required=True, type=Path)
    v = sub.add_parser("verify")
    for arg in ["mapping", "core-archive", "adapter-archive", "core-sbom", "adapter-sbom"]:
        v.add_argument("--" + arg, required=True, type=Path)
    v.add_argument("--commit", required=True)
    args = parser.parse_args()
    if args.mode == "inspect":
        report = inspect_adapter(args.archive, args.lockfile, args.workspace_manifest, args.commit)
    elif args.mode == "aggregate":
        report = aggregate(args.core_archive, args.adapter_archive,
                           args.core_evidence, args.adapter_evidence,
                           args.core_sbom, args.adapter_sbom,
                           args.lockfile, args.workspace_manifest, args.commit)
    else:
        report = json.loads(args.mapping.read_text(encoding="utf-8"))
        verify_mapping(report, args.core_archive, args.adapter_archive,
                       args.core_sbom, args.adapter_sbom, args.commit)
        print("Paired release subject hashes and source ref are consistent")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("schema", "commit")}, sort_keys=True))


if __name__ == "__main__":
    main()
