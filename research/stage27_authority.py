"""Stage 27 software-rooted attestation authority manifest.

The authority job is a separate GitHub Actions trust domain. It derives only
static, reviewable facts from the checked-out repository and signs the canonical
manifest with an ephemeral Ed25519 key generated inside that job. The private
key is never uploaded.

This is intentionally a software-rooted experiment, not hardware attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


LOGICAL_NSSF_SERVICES = ("nssf", "nssf2")
EXPECTED_NSSF_COUNT = 2
EXPECTED_REGISTERED_COUNT = 2
MANIFEST_SCHEMA = "stage27-software-attestation-v1"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_manifest(repo_root: Path) -> dict:
    config_paths = {
        "nssf": repo_root / "live" / "nssf.yaml",
        "nssf2": repo_root / "live" / "nssf2.yaml",
    }
    for path in config_paths.values():
        if not path.is_file():
            raise FileNotFoundError(path)

    return {
        "stage": 27,
        "schema": MANIFEST_SCHEMA,
        "authority_model": "github_actions_ephemeral_ed25519_job",
        "open5gs_ref": "v2.7.6",
        "expected_nssf_count": EXPECTED_NSSF_COUNT,
        "expected_registered_count": EXPECTED_REGISTERED_COUNT,
        "logical_nssf_services": list(LOGICAL_NSSF_SERVICES),
        "config_sha256": {
            name: sha256_file(path)
            for name, path in sorted(config_paths.items())
        },
        "github_repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "github_sha": os.environ.get("GITHUB_SHA", ""),
        "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "github_workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "claim_scope": (
            "software-rooted signed baseline for expected NSSF cardinality "
            "and REGISTERED-state count; no runtime UUID attestation"
        ),
    }


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="stage27_authority")
    args = parser.parse_args()

    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest(Path("."))

    (root / "manifest.json").write_bytes(
        canonical_bytes(manifest)
    )
    (root / "manifest.pretty.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf8",
    )

    print(
        "STAGE27_AUTHORITY_MANIFEST_OK "
        f"expected_nssf_count={manifest['expected_nssf_count']} "
        f"sha={manifest['github_sha']}",
        flush=True,
    )


if __name__ == "__main__":
    main()
