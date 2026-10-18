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
# Reviewed direct SDK dependencies, including feature-gated Rust AST
# parsers and the pinned ASN.1 OID parser required for safe canonicalization.
# Any addition requires explicit supply-chain review and adversarial tests.
EXPECTED_DIRECT = {
    "serde", "serde_json", "sha2", "cap-std", "cap-fs-ext",
    "proc-macro2", "syn", "toml", "toml_edit", "x509-cert",
    "const-oid",
}
CREATED = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def _locked_contract(lockfile: Path) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Resolve exact *direct* versions, allowing explicitly pinned duplicates.

    Cargo.lock can contain syn 2 (transitive) and syn 3 (direct). Cargo
    qualifies the root reference as "syn 3.0.9" in that case. Never infer
    which version is direct from its name or a sorted candidate list.
    """
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
    root_refs: dict[str, str | None] = {}
    for dependency in deps:
        parts = dependency.split()
        if (len(parts) not in (1, 2) or parts[0] not in EXPECTED_DIRECT
                or parts[0] in root_refs
                or (len(parts) == 2 and not re.fullmatch(
                    r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", parts[1]
                ))):
            raise ValueError("direct dependency contract changed or ambiguous")
        root_refs[parts[0]] = parts[1] if len(parts) == 2 else None
    if set(root_refs) != EXPECTED_DIRECT:
        raise ValueError("direct dependency contract changed or ambiguous")

    direct: dict[str, str] = {}
    all_versions: dict[str, set[str]] = {}
    for name in sorted(EXPECTED_DIRECT):
        available = [
            p.get("version") for p in packages
            if isinstance(p, dict) and p.get("name") == name
        ]
        if not available or not all(isinstance(v, str) and v for v in available):
            raise ValueError(f"missing or ambiguous locked version for {name}")
        all_versions[name] = set(available)
        requested = root_refs[name]
        candidates = available if requested is None else [v for v in available if v == requested]
        if len(candidates) != 1:
            raise ValueError(f"missing or ambiguous locked version for {name}")
        direct[name] = candidates[0]
    return direct, all_versions


def locked_direct_versions(lockfile: Path) -> dict[str, str]:
    """Derive the uniquely identified direct dependency versions."""
    direct, _ = _locked_contract(lockfile)
    return direct


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

    locked_versions, allowed_versions = _locked_contract(lockfile)
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
            # A second, *transitive* version is valid only when its exact
            # version also occurs in the reviewed lockfile. Direct coverage
            # still requires the explicit root-selected version.
            if version not in allowed_versions[name]:
                raise ValueError(f"SBOM version differs from Cargo.lock for {name}")
            if version == locked_versions[name]:
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
