#!/usr/bin/env python3
"""Validate a packaged .crate and emit deterministic, unsigned release evidence.

This is an inspection manifest, NOT an SBOM or an authenticity attestation.
"""
import argparse
import hashlib
import json
import re
import tarfile
import tomllib
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 30 * 1024 * 1024
MAX_ENTRIES = 5000
BAD_PARTS = {".git", ".env", "__pycache__", "target", ".ssh"}
BAD_SUFFIXES = {".pem", ".p12", ".pfx", ".key", ".env"}
REQUIRED = {"Cargo.toml", "README.md", "LICENSE-APACHE", "LICENSE-MIT"}


def inspect(archive: Path, commit: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("expected a 40-character Git commit SHA")
    if not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("missing or oversized archive")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    entries = []
    names = set()
    manifest = None
    expanded = 0
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if not members or len(members) > MAX_ENTRIES:
            raise ValueError("invalid member count")
        root = members[0].name.split("/", 1)[0]
        if not re.fullmatch(r"cryptomap-[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", root):
            raise ValueError("unexpected package root")
        for member in members:
            name = member.name
            path = PurePosixPath(name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or len(path.parts) < 2
                or path.parts[0] != root
                or not (member.isfile() or member.isdir())
                or member.issym()
                or member.islnk()
            ):
                raise ValueError("unsafe archive entry")
            rel = "/".join(path.parts[1:])
            if any(part in BAD_PARTS or part.startswith(".env") for part in path.parts[1:]):
                raise ValueError("forbidden packaged directory or file")
            if member.isfile() and (path.suffix.lower() in BAD_SUFFIXES):
                raise ValueError("potential secret-bearing packaged filename")
            if member.isfile():
                if rel in names:
                    raise ValueError("duplicate packaged path")
                names.add(rel)
                expanded += member.size
                if expanded > MAX_ARCHIVE:
                    raise ValueError("expanded archive budget exceeded")
                if rel == "Cargo.toml":
                    if member.size > 100_000:
                        raise ValueError("oversized Cargo.toml")
                    stream = tar.extractfile(member)
                    if stream is None:
                        raise ValueError("missing manifest contents")
                    manifest = tomllib.loads(stream.read().decode("utf-8"))
                entries.append({"path": rel, "size": member.size})
    if not REQUIRED <= names or manifest is None:
        raise ValueError("missing release-critical package files")
    pkg = manifest.get("package", {})
    version = pkg.get("version")
    if pkg.get("name") != "cryptomap" or not isinstance(version, str):
        raise ValueError("invalid crate metadata")
    if root != f"cryptomap-{version}":
        raise ValueError("archive root/version mismatch")
    # The release candidate remains explicitly unpublishable until approved.
    if pkg.get("publish") is not False:
        raise ValueError("prematurely enabled publication")
    return {
        "schema": "cryptomap:release-evidence:v1",
        "commit": commit,
        "archive": archive.name,
        "sha256": digest,
        "crate": "cryptomap",
        "version": version,
        "publish_enabled": False,
        "files": sorted(entries, key=lambda e: e["path"]),
        "limitations": [
            "unsigned inspection record, not SLSA provenance",
            "not an SPDX or CycloneDX SBOM",
            "not verification of a registry-distributed crate",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = inspect(args.archive, args.commit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {report['archive']} sha256={report['sha256']}")


if __name__ == "__main__":
    main()
