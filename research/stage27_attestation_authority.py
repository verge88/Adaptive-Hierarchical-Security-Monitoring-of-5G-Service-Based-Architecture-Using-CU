"""Stage 27 software-rooted attestation authority.

The authority is intentionally separate from the compromised NRF/NF-witness
jobs.  It signs a deployment-state contract with an ephemeral Ed25519 key.
Only the public key, canonical manifest and signature are exported.

This is a software-rooted GitHub Actions trust domain, not hardware attestation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

SCHEMA = "stage27-software-attested-nf-state-v1"


def canonical_json(obj: dict) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_manifest(repo_root: Path) -> dict:
    """Build the predeclared truth contract without reading runtime NRF/NF state."""
    return {
        "schema": SCHEMA,
        "trust_domain": "stage27-github-actions-software-attestation-authority",
        "open5gs_source_ref": "v2.7.6",
        "expected_profiles": [
            {
                "slot": "nssf-1",
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
            },
            {
                "slot": "nssf-2",
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
            },
        ],
        "deployment_contract": {
            "nssf_config_sha256": sha256_file(repo_root / "live/nssf.yaml"),
            "nssf2_config_sha256": sha256_file(repo_root / "live/nssf2.yaml"),
            "expected_nssf_count": 2,
        },
        "github_provenance": {
            "repository": os.environ.get("GITHUB_REPOSITORY", ""),
            "sha": os.environ.get("GITHUB_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        },
    }


def run(args: list[str]) -> None:
    subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def create_bundle(repo_root: Path, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest(repo_root)
    manifest_bytes = canonical_json(manifest)
    manifest_path = output / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)

    with tempfile.TemporaryDirectory(prefix="stage27-attestor-") as tmp:
        tmp_path = Path(tmp)
        private_key = tmp_path / "private.pem"
        public_key = output / "public_key.pem"
        signature = output / "signature.bin"

        run([
            "openssl", "genpkey",
            "-algorithm", "ED25519",
            "-out", str(private_key),
        ])
        run([
            "openssl", "pkey",
            "-in", str(private_key),
            "-pubout",
            "-out", str(public_key),
        ])
        run([
            "openssl", "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey", str(private_key),
            "-in", str(manifest_path),
            "-out", str(signature),
        ])

        private_fingerprint = hashlib.sha256(private_key.read_bytes()).hexdigest()
        private_key.unlink()
        if private_key.exists():
            raise AssertionError("Stage27 private attestation key was not destroyed")

    public_fingerprint = hashlib.sha256(public_key.read_bytes()).hexdigest()
    signature_b64 = base64.b64encode(signature.read_bytes()).decode("ascii")
    provenance = {
        "stage": 27,
        "schema": SCHEMA,
        "algorithm": "Ed25519",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "public_key_sha256": public_fingerprint,
        "signature_base64": signature_b64,
        "private_key_exported": False,
        "private_key_destroyed_before_artifact_upload": True,
        "private_key_ephemeral_fingerprint_not_exported": bool(private_fingerprint),
        "authority_reads_runtime_nrf_discovery": False,
        "authority_reads_runtime_nf_witness": False,
        "claim_scope": (
            "software-rooted signed deployment-state contract in an isolated "
            "GitHub Actions job; not TPM/TEE runtime attestation"
        ),
    }
    (output / "provenance.json").write_text(
        json.dumps(provenance, indent=2),
        encoding="utf8",
    )
    return provenance


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--output", default="stage27_attestation_public")
    args = parser.parse_args()
    provenance = create_bundle(Path(args.repo_root), Path(args.output))
    print(
        "STAGE27_ATTESTATION_AUTHORITY_OK "
        f"manifest_sha256={provenance['manifest_sha256']} "
        f"public_key_sha256={provenance['public_key_sha256']} "
        "private_key_exported=false",
        flush=True,
    )


if __name__ == "__main__":
    main()
