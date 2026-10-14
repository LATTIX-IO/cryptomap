#!/usr/bin/env python3
"""Validate SPDX 2.3 software SBOM identity and exact reviewed Cargo.lock versions.

This SDK build inventory is NOT a Cryptomap cryptographic bill of materials.
"""
import argparse
import json
import re
import tomllib
from pathlib import Path

MAX_SBOM_BYTES = 16 * 1024 * 1024
MAX_LOCK_BYTES = 8 * 1024 * 1024
# Reviewed direct SDK dependencies, including feature-gated Rust AST parsers.
# Any addition requires explicit supply-chain review and adversarial tests.
EXPECTED_DIRECT = {
    "serde", "serde_json", "sha2", "cap-std", "cap-fs-ext",
    "proc-macro2", "syn", "toml",
}
CREATED = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def locked_direct_versions(lockfile: Path) -> dict[str, str]:
    """Derive exact direct dependency versions from reviewed Cargo.lock v4."""
    if not lockfile.is_file() or not 0 < lockfile.stat().st_size <= MAX_LOCK_BYTES:
        raise ValueError("missing or oversized reviewed Cargo.lock")
    with lockfile.open("rb") as stream:
        lock = tomllib.load(stream)
    if not isinstance(lock, dict) or lock.get("version") != 4:
        raise ValueError("unsupported Cargo.lock version")
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ValueError("missing Cargo.lock packages")
    roots = [item for item in packages if isinstance(item, dict) and item.get("name") == "cryptomap"]
    if len(roots) != 1:
        raise ValueError("missing or ambiguous cryptomap root in Cargo.lock")
    deps = roots[0].get("dependencies")
    if not isinstance(deps, list) or not all(isinstance(d, str) and d for d in deps):
        raise ValueError("invalid cryptomap root dependencies")
    # A dependency can include a locked version suffix if multiple versions
    # exist; reject that ambiguity rather than guessing the resolved artifact.
    if any(len(d.split()) != 1 for d in deps) or set(deps) != EXPECTED_DIRECT:
        raise ValueError("direct dependency contract changed or ambiguous")
    result = {}
    for name in sorted(EXPECTED_DIRECT):
        matches = [
            item.get("version") for item in packages
            if isinstance(item, dict) and item.get("name") == name
        ]
        if len(matches) != 1 or not isinstance(matches[0], str) or not matches[0]:
            raise ValueError(f"missing or ambiguous locked version for {name}")
        result[name] = matches[0]
    return result


def validate(path: Path, lockfile: Path) -> dict:
    """Reject invalid SPDX structure and every unbound direct dependency version."""
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_SBOM_BYTES:
        raise ValueError("missing or oversized SPDX SBOM")
    with path.open("r", encoding="utf-8") as stream:
        report = json.load(stream)
    if not isinstance(report, dict) or report.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("expected SPDX-2.3 JSON")
    if report.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ValueError("missing SPDX document identity")
    for field in ("name", "documentNamespace"):
        if not isinstance(report.get(field), str) or not report[field].strip():
            raise ValueError(f"missing SPDX document {field}")
    if report.get("dataLicense") != "CC0-1.0":
        raise ValueError("missing SPDX data license")
    creation = report.get("creationInfo")
    if not isinstance(creation, dict):
        raise ValueError("missing SPDX creation metadata")
    creators = creation.get("creators")
    if not isinstance(creators, list) or not creators or not all(
        isinstance(c, str) and c.strip() for c in creators
    ):
        raise ValueError("missing SPDX creators")
    created = creation.get("created")
    if not isinstance(created, str) or not CREATED.fullmatch(created):
        raise ValueError("missing or invalid SPDX creation timestamp")

    locked_versions = locked_direct_versions(lockfile)
    packages = report.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("empty dependency inventory")
    seen_ids = set()
    observed = set()
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("invalid SPDX package")
        spdx_id = package.get("SPDXID")
        if not isinstance(spdx_id, str) or not spdx_id.startswith("SPDXRef-"):
            raise ValueError("invalid package SPDXID")
        if spdx_id in seen_ids:
            raise ValueError("duplicate package SPDXID")
        seen_ids.add(spdx_id)
        name, version = package.get("name"), package.get("versionInfo")
        if not isinstance(name, str) or not name:
            raise ValueError("unnamed dependency")
        download = package.get("downloadLocation")
        if not isinstance(download, str) or not download.strip():
            raise ValueError("missing SPDX package downloadLocation")
        if name in locked_versions:
            if not isinstance(version, str) or not version:
                raise ValueError(f"unversioned required Rust dependency {name}")
            if version != locked_versions[name]:
                raise ValueError(f"SBOM version differs from Cargo.lock for {name}")
            observed.add(name)
    missing = EXPECTED_DIRECT - observed
    if missing:
        raise ValueError("missing locked direct dependencies: " + ", ".join(sorted(missing)))
    return {
        "spdxVersion": report["spdxVersion"],
        "package_count": len(packages),
        "direct_dependency_versions": locked_versions,
    }


def main() -> None:
    """Validate SPDX and exact Cargo.lock without network access."""
    parser = argparse.ArgumentParser()
    parser.add_argument("sbom", type=Path)
    parser.add_argument("--lockfile", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.sbom, args.lockfile), sort_keys=True))


if __name__ == "__main__":
    main()
