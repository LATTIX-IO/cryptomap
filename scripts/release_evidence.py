#!/usr/bin/env python3
"""Validate a packaged .crate and emit deterministic, unsigned release evidence.

This is an inspection manifest, NOT an SBOM or an authenticity attestation.
"""
import argparse
import gzip
import hashlib
import json
import re
import tarfile
import tomllib
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 30 * 1024 * 1024
MAX_ENTRIES = 5000
# Bound data consumed by tarfile itself, including invisible PAX/GNU headers.
MAX_TAR_STREAM = MAX_ARCHIVE + MAX_ENTRIES * 2048 + 2 * 1024 * 1024
BAD_PARTS = {".git", ".env", "__pycache__", "target", ".ssh"}
BAD_SUFFIXES = {".pem", ".p12", ".pfx", ".key", ".env"}
REQUIRED = {"Cargo.toml", "README.md", "LICENSE-APACHE", "LICENSE-MIT"}


class BoundedDecompressedStream:
    """Cap decompressed reads before tarfile parses untrusted extensions."""

    def __init__(self, reader, max_bytes: int) -> None:
        self.reader = reader
        self.max_bytes = max_bytes
        self.consumed = 0

    def read(self, size: int = -1) -> bytes:
        """Reject decompressed input beyond the ceiling, including PAX data."""
        remaining_plus_probe = self.max_bytes - self.consumed + 1
        if size < 0 or size > remaining_plus_probe:
            size = remaining_plus_probe
        data = self.reader.read(size)
        self.consumed += len(data)
        if self.consumed > self.max_bytes:
            raise ValueError("decompressed tar stream budget exceeded")
        return data


def audit_physical_tar_layout(archive: Path, expected_members: int) -> None:
    """Independently validate physical headers hidden by tarfile's PAX layer.

    The high-level iterator may swallow malformed noninitial members or PAX
    overrides. This bounded second pass checks every physical TAR record,
    rejects size/link overrides, and compares the physical regular/directory
    member count to records actually yielded by the parser.
    """
    def exact(stream: BoundedDecompressedStream, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = stream.read(min(65536, size - len(data)))
            if not chunk:
                raise ValueError("truncated physical tar stream")
            data.extend(chunk)
        return bytes(data)

    def octal(field: bytes) -> int:
        if field and field[0] & 0x80:
            raise ValueError("unsupported binary tar size")
        raw = field.strip(b" \x00")
        if not raw or any(byte not in b"01234567" for byte in raw):
            raise ValueError("malformed tar numeric field")
        return int(raw, 8)

    def reject_pax_unsafe(payload: bytes) -> None:
        pos = 0
        while pos < len(payload):
            space = payload.find(b" ", pos)
            if space <= pos:
                raise ValueError("invalid PAX record")
            digits = payload[pos:space]
            if not digits.isdigit() or len(digits) > 9:
                raise ValueError("invalid PAX record size")
            length = int(digits)
            record = payload[pos:pos + length]
            if length <= space - pos + 3 or len(record) != length or not record.endswith(b"\n"):
                raise ValueError("invalid PAX record length")
            attribute = record[space - pos + 1:].split(b"=", 1)[0]
            if attribute in (b"size", b"linkpath") or attribute.startswith(b"GNU.sparse"):
                raise ValueError("unsafe PAX size/link override")
            pos += length

    with archive.open("rb") as raw, gzip.GzipFile(fileobj=raw) as uncompressed:
        stream = BoundedDecompressedStream(uncompressed, MAX_TAR_STREAM)
        count = 0
        pending = False
        while True:
            header = exact(stream, 512)
            if not any(header):
                if pending or any(exact(stream, 512)):
                    raise ValueError("missing canonical tar terminator")
                while True:
                    trailing = stream.read(65536)
                    if not trailing:
                        break
                    if any(trailing):
                        raise ValueError("nonzero bytes after tar terminator")
                break
            checksum = octal(header[148:156])
            unsigned = sum(header[:148]) + 8 * ord(" ") + sum(header[156:])
            if checksum != unsigned:
                raise ValueError("invalid physical tar header checksum")
            size = octal(header[124:136])
            if size > MAX_ARCHIVE:
                raise ValueError("physical tar member exceeds byte budget")
            flag = header[156:157]
            if flag not in (b"0", b"\x00", b"5", b"x", b"g", b"L"):
                raise ValueError("unsupported physical tar member type")
            if flag in (b"0", b"\x00", b"5"):
                count += 1
                if count > MAX_ENTRIES:
                    raise ValueError("physical member budget exceeded")
                pending = False
            elif flag in (b"x", b"L"):
                pending = True
            if flag in (b"x", b"g"):
                reject_pax_unsafe(exact(stream, size))
            else:
                remaining = size
                while remaining:
                    chunk = exact(stream, min(65536, remaining))
                    remaining -= len(chunk)
            pad = (-size) % 512
            if pad and any(exact(stream, pad)):
                raise ValueError("nonzero physical tar padding")
        if count != expected_members:
            raise ValueError("tar parser skipped or invented members")


def expected_workspace_version(manifest_path: Path, lockfile_path: Path) -> str:
    """Bind release identity to a bounded reviewed workspace and Cargo.lock."""
    if not manifest_path.is_file() or not 0 < manifest_path.stat().st_size <= 100_000:
        raise ValueError("missing or oversized workspace Cargo.toml")
    if not lockfile_path.is_file() or not 0 < lockfile_path.stat().st_size <= 8 * 1024 * 1024:
        raise ValueError("missing or oversized reviewed Cargo.lock")
    with manifest_path.open("rb") as stream:
        workspace = tomllib.load(stream)
    with lockfile_path.open("rb") as stream:
        locked = tomllib.load(stream)
    version = workspace.get("workspace", {}).get("package", {}).get("version")
    if not isinstance(version, str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version
    ):
        raise ValueError("invalid workspace release version")
    roots = [
        package for package in locked.get("package", [])
        if isinstance(package, dict) and package.get("name") == "cryptomap"
    ]
    if len(roots) != 1 or roots[0].get("version") != version:
        raise ValueError("workspace/Cargo.lock root version mismatch")
    return version


def inspect(archive: Path, commit: str, expected_version: str) -> dict:
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
    # Stream headers; the lower-level read ceiling also protects against
    # PAX/GNU extension records consumed inside tarfile before yielding a member.
    with archive.open("rb") as raw, gzip.GzipFile(fileobj=raw) as uncompressed:
        bounded = BoundedDecompressedStream(uncompressed, MAX_TAR_STREAM)
        with tarfile.open(fileobj=bounded, mode="r|") as tar:
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
    audit_physical_tar_layout(archive, count)
    if not REQUIRED <= files or manifest is None:
        raise ValueError("missing release-critical package files")
    pkg = manifest.get("package", {})
    version = pkg.get("version")
    if pkg.get("name") != "cryptomap" or not isinstance(version, str):
        raise ValueError("invalid crate metadata")
    if root != f"cryptomap-{version}":
        raise ValueError("archive root/version mismatch")
    if version != expected_version:
        raise ValueError("archive version differs from checked-out workspace")
    if archive.name != f"{root}.crate":
        raise ValueError("archive filename/version mismatch")
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
    parser.add_argument("--workspace-manifest", required=True, type=Path)
    parser.add_argument("--lockfile", required=True, type=Path)
    args = parser.parse_args()
    approved_version = expected_workspace_version(args.workspace_manifest, args.lockfile)
    report = inspect(args.archive, args.commit, approved_version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {report['archive']} sha256={report['sha256']}")


if __name__ == "__main__":
    main()
