"""Stage 28 verifier: freeze the Stage-27 software attestation mechanism.

Stage 28 changes the attack distribution, not the trust mechanism. The same
canonical Stage-27 authority manifest and Ed25519 verification rules are reused.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .stage27_attestation import (
    canonical_bytes,
    project,
    validate_manifest,
    verify_ed25519,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-telemetry", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--output", default="stage28_projected")
    args = parser.parse_args()

    raw_path = Path(args.raw_telemetry)
    manifest_path = Path(args.manifest)
    signature_path = Path(args.signature)
    public_key_path = Path(args.public_key)

    verify_ed25519(manifest_path, signature_path, public_key_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf8"))
    if canonical_bytes(manifest) != manifest_path.read_bytes():
        raise ValueError("Stage28 authority manifest is not canonical JSON")
    validate_manifest(manifest)

    raw_rows = json.loads(raw_path.read_text(encoding="utf8"))
    if not raw_rows:
        raise ValueError("Empty Stage28 raw telemetry")

    attested, compromised = project(raw_rows, manifest)
    seed = int(raw_rows[0]["seed"])
    if any(int(row["seed"]) != seed for row in raw_rows):
        raise ValueError("Mixed seeds in Stage28 raw telemetry")

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "attested_telemetry.json").write_text(
        json.dumps(attested, indent=2), encoding="utf8"
    )
    (output / "compromised_pair_telemetry.json").write_text(
        json.dumps(compromised, indent=2), encoding="utf8"
    )

    provenance = {
        "stage": 28,
        "seed": seed,
        "trust_mechanism_frozen_from_stage27": True,
        "attestation_signature_verified": True,
        "attestation_algorithm": "Ed25519",
        "authority_private_key_available_to_verifier": False,
        "authority_private_key_uploaded": False,
        "manifest_sha256": hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest(),
        "public_key_sha256": hashlib.sha256(
            public_key_path.read_bytes()
        ).hexdigest(),
        "manifest_github_repository": manifest["github_repository"],
        "manifest_github_sha": manifest["github_sha"],
        "manifest_github_run_id": manifest["github_run_id"],
        "manifest_expected_nssf_count": manifest["expected_nssf_count"],
        "manifest_expected_registered_count": (
            manifest["expected_registered_count"]
        ),
        "pairwise_common_source_equal_in_raw_input": all(
            int(row["consumer_nssf_count"])
            == int(row["compromised_witness_nssf_count"])
            and int(row["consumer_registered_count"])
            == int(row["compromised_witness_registered_count"])
            for row in raw_rows
        ),
    }
    (output / "attestation_provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf8"
    )

    print(
        "STAGE28_ATTESTATION_VERIFY_OK "
        f"seed={seed} manifest={provenance['manifest_sha256']}",
        flush=True,
    )


if __name__ == "__main__":
    main()
