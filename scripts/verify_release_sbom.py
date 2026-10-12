#!/usr/bin/env python3
"""Validate a tool-generated SPDX software SBOM for the locked Rust SDK build.

Do not confuse this repository/dependency SBOM with a Cryptomap CBOM export.
"""
import argparse
import json
from pathlib import Path

MAX_SBOM_BYTES = 16 * 1024 * 1024
EXPECTED_DIRECT = {"serde", "serde_json", "sha2", "cap-std", "cap-fs-ext"}


def validate(path: Path) -> dict:
    """Fail if SPDX 2.3 structure or essential locked dependencies are missing."""
    if not path.is_file() or path.stat().st_size > MAX_SBOM_BYTES:
        raise ValueError("missing or oversized SPDX SBOM")
    with path.open("r", encoding="utf-8") as stream:
        report = json.load(stream)
    if not isinstance(report, dict) or report.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("expected SPDX-2.3 JSON")
    if report.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ValueError("missing SPDX document identity")
    if report.get("dataLicense") != "CC0-1.0" or not report.get("documentNamespace"):
        raise ValueError("missing SPDX document metadata")
    creation = report.get("creationInfo")
    if not isinstance(creation, dict) or not creation.get("creators"):
        raise ValueError("missing SPDX creation metadata")
    packages = report.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("empty dependency inventory")
    seen_ids = set()
    seen_names = set()
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
        if name in EXPECTED_DIRECT and (not isinstance(version, str) or not version):
            raise ValueError("unversioned required Rust dependency")
        seen_names.add(name)
    missing = EXPECTED_DIRECT - seen_names
    if missing:
        raise ValueError("missing locked direct dependencies: " + ", ".join(sorted(missing)))
    return {
        "spdxVersion": report["spdxVersion"],
        "package_count": len(packages),
        "direct_dependency_names_present": sorted(EXPECTED_DIRECT),
    }


def main() -> None:
    """Validate the generated file and emit only aggregate verification data."""
    parser = argparse.ArgumentParser()
    parser.add_argument("sbom", type=Path)
    args = parser.parse_args()
    result = validate(args.sbom)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
