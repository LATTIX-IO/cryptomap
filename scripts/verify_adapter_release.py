#!/usr/bin/env python3
"""FOSS-486: bounded inspection and exact locked provenance for an unpublished adapter.

These records are unsigned release inspection evidence. GitHub main-only
attestations (never this script) establish provenance after policy acceptance.
"""
from __future__ import annotations

import argparse
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
EXPECTED_DIRECT = {CORE, "windows-sys", "x509-cert"}
EXPECTED_FILES = {
    "Cargo.toml", "README.md", "LICENSE-MIT", "LICENSE-APACHE",
    "src/lib.rs", "examples/read_user_store.rs",
    "examples/fixtures/certificate/rsa.pem",
    "examples/fixtures/certificate/ec.pem",
}
OPTIONAL_CARGO_FILES = {"Cargo.toml.orig", ".cargo_vcs_info.json"}
ALLOWED_FILES = EXPECTED_FILES | OPTIONAL_CARGO_FILES
ALLOWED_DIRS = {
    "/".join(path.split("/")[:index])
    for path in ALLOWED_FILES
    for index in range(1, len(path.split("/")))
}
CERT_PREFIX = "examples/fixtures/certificate/"
BAD_IDENTIFIERS = {"..", ".git", ".ssh", "target", ".env", "__pycache__"}
COMMIT = re.compile(r"[a-f0-9]{40}")
SPDX_CREATED = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")


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
    if not EXPECTED_FILES <= regular_files or manifest is None:
        raise ValueError("adapter archive missing mandatory files")
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
        "registry_resolvable": False,
        "limitations": ["unsigned", "path-paired source distribution only",
                        "not a crates.io install or code-signing authority"],
    }


def validate_adapter_spdx(path: Path, lockfile: Path, version: str) -> dict:
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
    adapter_spdx = validate_adapter_spdx(adapter_sbom, lockfile, version)
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
