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
    """Inspect a bounded, untrusted release archive without extracting it."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("expected a 40-character Git commit SHA")
    if not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("missing or oversized archive")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    entries = []
    names = set()
    files = set()
    manifest = None
    expanded = 0
    root = None
    count = 0
    # Stream headers: never call getmembers(), which eagerly materializes
    # untrusted metadata before MAX_ENTRIES / expanded-size checks.
    with tarfile.open(archive, "r|gz") as tar:
        for member in tar:
            count += 1
            if count > MAX_ENTRIES:
                raise ValueError("archive member budget exceeded")
            name = member.name
            if root is None:
                root = name.split("/", 1)[0]
                if not re.fullmatch(r"cryptomap-[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", root):
                    raise ValueError("unexpected package root")
            path = PurePosixPath(name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or len(path.parts) < 2
                or path.parts[0] != root
                or path.as_posix() != name.rstrip("/")
                or not (member.isfile() or member.isdir())
                or member.issym()
                or member.islnk()
            ):
                raise ValueError("unsafe archive entry")
            rel = "/".join(path.parts[1:])
            # Track directories and files alike; file/directory collisions and
            # file-as-parent paths are ambiguous at extraction time.
            if rel in names or any("/".join(path.parts[1:i]) in files for i in range(2, len(path.parts))):
                raise ValueError("duplicate or overlapping packaged path")
            if member.isfile() and any(existing.startswith(rel + "/") for existing in names):
                raise ValueError("file shadows packaged directory")
            names.add(rel)
            if any(part in BAD_PARTS or part.startswith(".env") for part in path.parts[1:]):
                raise ValueError("forbidden packaged directory or file")
            if member.isfile() and (path.suffix.lower() in BAD_SUFFIXES):
                raise ValueError("potential secret-bearing packaged filename")
            if member.isfile():
                files.add(rel)
                expanded += member.size
                # Reject declared sizes before consuming or seeking past data.
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
    if count == 0:
        raise ValueError("empty archive")
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
    """Provide a CLI that writes sorted unsigned release inspection evidence."""
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
