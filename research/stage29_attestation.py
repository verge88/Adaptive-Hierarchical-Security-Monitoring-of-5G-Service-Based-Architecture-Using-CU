"""Stage 29 attestation projection.

The Stage-27/28 signature-verification mechanism is frozen. Stage 29 adds only
an explicit marker to the label-free projected rows so the blind detector can
distinguish a cryptographically verified reference from the colluding negative
control without seeing any attack schedule.
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
    parser.add_argument("--output", default="stage29_projected")
    args = parser.parse_args()

    raw_path = Path(args.raw_telemetry)
    manifest_path = Path(args.manifest)
    signature_path = Path(args.signature)
    public_key_path = Path(args.public_key)

    verify_ed25519(manifest_path, signature_path, public_key_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf8"))
    if canonical_bytes(manifest) != manifest_path.read_bytes():
        raise ValueError("Stage29 authority manifest is not canonical JSON")
    validate_manifest(manifest)

    raw_rows = json.loads(raw_path.read_text(encoding="utf8"))
    if not raw_rows:
        raise ValueError("Empty Stage29 raw telemetry")

    attested, compromised = project(raw_rows, manifest)
    seed = int(raw_rows[0]["seed"])
    if any(int(row["seed"]) != seed for row in raw_rows):
        raise ValueError("Mixed seeds in Stage29 raw telemetry")

    for row in attested:
        row["stage29_attestation_verified_reference"] = True
    for row in compromised:
        row["stage29_attestation_verified_reference"] = False

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "attested_telemetry.json").write_text(
        json.dumps(attested, indent=2), encoding="utf8"
    )
    (output / "compromised_pair_telemetry.json").write_text(
        json.dumps(compromised, indent=2), encoding="utf8"
    )

    provenance = {
        "stage": 29,
        "seed": seed,
        "trust_mechanism_frozen_from_stage27": True,
        "projection_mechanism_frozen_from_stage28": True,
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
        "realized_attack_schedule_available_to_verifier": False,
    }
    (output / "attestation_provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf8"
    )

    print(
        "STAGE29_ATTESTATION_VERIFY_OK "
        f"seed={seed} manifest={provenance['manifest_sha256']}",
        flush=True,
    )


if __name__ == "__main__":
    main()
