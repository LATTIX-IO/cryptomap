#!/usr/bin/env python3
"""Fail closed on first-release approval, checked-out version and exact main CI.

This tool does not publish, read credentials, or authorize registry ownership.
"""
import argparse
import json
import re
import tomllib
from pathlib import Path

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_VERSION = re.compile(r"0\.[0-9]+\.[0-9]+-alpha\.[1-9][0-9]*\Z")
_REPO = "LATTIX-IO/cryptomap"


def select_verified_ci_run(payload: object, sha: str, repository: str) -> int:
    """Select only completed successful push CI for the exact reviewed main SHA."""
    if not _SHA.fullmatch(sha) or repository != _REPO:
        raise ValueError("unapproved repository or commit SHA")
    if not isinstance(payload, dict) or not isinstance(payload.get("workflow_runs"), list):
        raise ValueError("missing GitHub Actions workflow evidence")
    verified = []
    for run in payload["workflow_runs"]:
        if not isinstance(run, dict):
            continue
        owner = run.get("repository")
        if (
            run.get("head_sha") != sha
            or run.get("event") != "push"
            or run.get("head_branch") != "main"
            or run.get("name") != "Rust CI"
            or run.get("path") != ".github/workflows/ci.yml"
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or not isinstance(owner, dict)
            or owner.get("full_name") != repository
        ):
            continue
        run_id = run.get("id")
        if isinstance(run_id, int) and not isinstance(run_id, bool) and run_id > 0:
            verified.append(run_id)
    if not verified:
        raise ValueError("no successful exact-SHA main Rust CI workflow")
    return max(verified)


def verify_release_manifest(manifest: Path, workspace: Path, approved_version: str) -> None:
    """Require an intentional crate registry allowlist and exact approved version."""
    if not _VERSION.fullmatch(approved_version):
        raise ValueError("invalid or unsupported alpha release version")
    package = tomllib.loads(manifest.read_text(encoding="utf-8")).get("package", {})
    workspace_package = tomllib.loads(workspace.read_text(encoding="utf-8")).get("workspace", {}).get(
        "package", {}
    )
    if (
        package.get("name") != "cryptomap"
        or package.get("publish") != ["crates-io"]
        or package.get("version") != {"workspace": True}
        or workspace_package.get("version") != approved_version
    ):
        raise ValueError("crate is not explicitly approved for this registry and version")


def main() -> None:
    """Print the verified CI run identifier for same-workflow artifact retrieval."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs-json", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    if args.runs_json.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("oversized workflow evidence")
    payload = json.loads(args.runs_json.read_text(encoding="utf-8"))
    run = select_verified_ci_run(payload, args.sha, args.repository)
    verify_release_manifest(args.manifest, args.workspace, args.version)
    print(run)


if __name__ == "__main__":
    main()
