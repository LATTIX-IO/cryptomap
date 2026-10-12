#!/usr/bin/env python3
"""Generate deterministic *source-package* release evidence from Cargo.lock.

SPDX-2.3 inventory covers lockfile-resolved packages, including packages that
may be target-conditional. This does not establish which binary dependencies
were compiled, their declared licenses, vulnerabilities, or an artifact
signature. No network, credentials, registry queries or source expansion.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import tomllib

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
PACKAGE = re.compile(r"^[A-Za-z0-9_-]+$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def make_evidence(lock_bytes: bytes, crate_bytes: bytes, version: str, commit: str, epoch: int):
    if not HEX64.fullmatch(commit) or not VERSION.fullmatch(version):
        raise ValueError("invalid commit or version")
    if epoch < 0:
        raise ValueError("negative build epoch")
    source = tomllib.loads(lock_bytes.decode("utf-8"))
    packages = source.get("package")
    if not isinstance(packages, list) or not packages:
        raise ValueError("Cargo.lock has no package inventory")

    artifacts = []
    seen = set()
    for record in packages:
        if not isinstance(record, dict):
            raise ValueError("malformed lockfile package")
        name, pinned = record.get("name"), record.get("version")
        origin = record.get("source", "")
        if not isinstance(name, str) or not PACKAGE.fullmatch(name):
            raise ValueError("invalid lockfile package name")
        if not isinstance(pinned, str) or not VERSION.fullmatch(pinned):
            raise ValueError("invalid lockfile package version")
        if not isinstance(origin, str) or len(origin) > 2048:
            raise ValueError("invalid source field")
        identity = (name, pinned, origin)
        if identity in seen:
            raise ValueError("duplicate locked package")
        seen.add(identity)
        spdx_id = "SPDXRef-Package-" + sha256_bytes("\x00".join(identity).encode("utf-8"))[:24]
        pkg = {
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": pinned,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if origin.startswith("registry+https://github.com/rust-lang/crates.io-index"):
            pkg["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:cargo/{name}@{pinned}",
            }]
        checksum = record.get("checksum")
        if checksum is not None:
            if not isinstance(checksum, str) or not HEX64.fullmatch(checksum):
                raise ValueError("invalid package checksum")
            pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum.lower()}]
        artifacts.append(pkg)

    artifacts.sort(key=lambda x: (x["name"], x["versionInfo"], x["SPDXID"]))
    checksum = sha256_bytes(crate_bytes)
    timestamp = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    root = next((p for p in artifacts if p["name"] == "cryptomap" and p["versionInfo"] == version), None)
    if root is None:
        raise ValueError("locked cryptomap root/version missing")

    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "cryptomap-" + version + "-Cargo.lock-software-package-inventory",
        "documentNamespace": "https://github.com/LATTIX-IO/cryptomap/release-evidence/sha256/" + checksum,
        "creationInfo": {"created": timestamp, "creators": ["Tool: cryptomap-release-evidence-1"]},
        "documentComment": "Lockfile package inventory, including conditional dependencies. No compiled graph, license conclusion, signature or completeness claim.",
        "packages": artifacts,
        "relationships": [{
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": root["SPDXID"],
            "relationshipType": "DESCRIBES",
        }],
    }
    receipt = {
        "schema_version": 1,
        "source_commit_sha": commit.lower(),
        "created_at": timestamp,
        "package": "cryptomap",
        "version": version,
        "crate_sha256": checksum,
        "cargo_lock_sha256": sha256_bytes(lock_bytes),
        "sbom_file": "cryptomap.spdx.json",
        "sbom_sha256": sha256_bytes(canonical_json(spdx)),
        "scope": "reviewed Cargo.lock package inventory; not a compiled dependency closure",
    }
    return spdx, receipt


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lock", type=pathlib.Path, required=True)
    ap.add_argument("--crate", type=pathlib.Path, required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--epoch", type=int, required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    args = ap.parse_args()
    spdx, receipt = make_evidence(
        args.lock.read_bytes(), args.crate.read_bytes(), args.version, args.commit, args.epoch
    )
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "cryptomap.spdx.json").write_bytes(canonical_json(spdx))
    (args.out / "release-evidence.json").write_bytes(canonical_json(receipt))
    # Verify both outputs after writing, including SBOM digests.
    loaded = json.loads((args.out / "cryptomap.spdx.json").read_text(encoding="utf-8"))
    if sha256_bytes(canonical_json(loaded)) != receipt["sbom_sha256"]:
        raise ValueError("written SBOM failed checksum verification")
    print("package_sha256=" + receipt["crate_sha256"])
    print("spdx_sha256=" + receipt["sbom_sha256"])


if __name__ == "__main__":
    main()
