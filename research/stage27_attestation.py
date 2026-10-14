"""Stage 27 signed-attestation verifier and detector-input projector."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from .h2_wire import encode
from .stage20_structure import serialize_counter, structural_counter
from .stage21_semantic import semantic_projection, serialize_projection
from .stage27_authority import (
    EXPECTED_NSSF_COUNT,
    EXPECTED_REGISTERED_COUNT,
    MANIFEST_SCHEMA,
    sha256_file,
)


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf8")


def verify_ed25519(
    manifest_path: Path,
    signature_path: Path,
    public_key_path: Path,
) -> None:
    proc = subprocess.run(
        [
            "openssl", "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey", str(public_key_path),
            "-in", str(manifest_path),
            "-sigfile", str(signature_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        raise ValueError(
            "Stage27 attestation signature verification failed: "
            + proc.stderr[-800:]
        )


def validate_manifest(manifest: dict) -> None:
    if int(manifest.get("stage", -1)) != 27:
        raise ValueError("Stage27 manifest stage mismatch")
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("Stage27 manifest schema mismatch")
    if int(manifest.get("expected_nssf_count", -1)) != EXPECTED_NSSF_COUNT:
        raise ValueError("Stage27 manifest NSSF count mismatch")
    if (
        int(manifest.get("expected_registered_count", -1))
        != EXPECTED_REGISTERED_COUNT
    ):
        raise ValueError("Stage27 manifest registered count mismatch")

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    if repo and manifest.get("github_repository") != repo:
        raise ValueError("Stage27 manifest repository mismatch")
    if sha and manifest.get("github_sha") != sha:
        raise ValueError("Stage27 manifest commit mismatch")

    expected_hashes = {
        "nssf": sha256_file(Path("live/nssf.yaml")),
        "nssf2": sha256_file(Path("live/nssf2.yaml")),
    }
    if manifest.get("config_sha256") != expected_hashes:
        raise ValueError("Stage27 manifest config hash mismatch")


def state_object(nssf_count: int, registered_count: int) -> dict:
    if nssf_count < 0 or registered_count < 0:
        raise ValueError("Negative Stage27 cardinality")
    if registered_count > nssf_count:
        raise ValueError("Registered count exceeds NSSF count")

    profiles = []
    for index in range(nssf_count):
        profiles.append(
            {
                "present": True,
                "registered": index < registered_count,
            }
        )
    return {"nssfProfiles": profiles}


def fields_for_state(nssf_count: int, registered_count: int) -> dict:
    obj = state_object(nssf_count, registered_count)
    payload_len = len(encode(obj))
    return {
        "status": 200,
        "canonical_bytes": payload_len,
        "nssf_profiles": nssf_count,
        "wire_bytes": payload_len,
        "structure": serialize_counter(structural_counter(obj)),
        "semantic": serialize_projection(semantic_projection(obj)),
    }


def row_from_states(
    raw: dict,
    trusted_count: int,
    trusted_registered: int,
    *,
    scope: str,
) -> dict:
    trusted = fields_for_state(trusted_count, trusted_registered)
    consumer = fields_for_state(
        int(raw["consumer_nssf_count"]),
        int(raw["consumer_registered_count"]),
    )
    return {
        "seed": int(raw["seed"]),
        "tick": int(raw["tick"]),
        "trusted_first": bool(raw["witness_first"]),
        "trusted_status": trusted["status"],
        "consumer_status": consumer["status"],
        "trusted_canonical_bytes": trusted["canonical_bytes"],
        "consumer_canonical_bytes": consumer["canonical_bytes"],
        "trusted_nssf_profiles": trusted["nssf_profiles"],
        "consumer_nssf_profiles": consumer["nssf_profiles"],
        "trusted_wire_bytes": trusted["wire_bytes"],
        "consumer_wire_bytes": consumer["wire_bytes"],
        "trusted_structure": trusted["structure"],
        "consumer_structure": consumer["structure"],
        "trusted_semantic": trusted["semantic"],
        "consumer_semantic": consumer["semantic"],
        "reference_scope": scope,
    }


def project(
    raw_rows: list[dict],
    manifest: dict,
) -> tuple[list[dict], list[dict]]:
    attested = []
    compromised_pair = []

    for raw in raw_rows:
        attested.append(
            row_from_states(
                raw,
                int(manifest["expected_nssf_count"]),
                int(manifest["expected_registered_count"]),
                scope="verified_signed_software_attestation",
            )
        )
        compromised_pair.append(
            row_from_states(
                raw,
                int(raw["compromised_witness_nssf_count"]),
                int(raw["compromised_witness_registered_count"]),
                scope="colluding_nrf_and_nf_side_witness",
            )
        )

    return attested, compromised_pair


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-telemetry", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--output", default="stage27_projected")
    args = parser.parse_args()

    raw_path = Path(args.raw_telemetry)
    manifest_path = Path(args.manifest)
    signature_path = Path(args.signature)
    public_key_path = Path(args.public_key)

    verify_ed25519(manifest_path, signature_path, public_key_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf8"))
    if canonical_bytes(manifest) != manifest_path.read_bytes():
        raise ValueError("Stage27 manifest is not canonical JSON")
    validate_manifest(manifest)

    raw_rows = json.loads(raw_path.read_text(encoding="utf8"))
    if not raw_rows:
        raise ValueError("Empty Stage27 raw telemetry")

    attested, compromised = project(raw_rows, manifest)
    seed = int(raw_rows[0]["seed"])
    if any(int(row["seed"]) != seed for row in raw_rows):
        raise ValueError("Mixed seeds in Stage27 raw telemetry")

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "attested_telemetry.json").write_text(
        json.dumps(attested, indent=2), encoding="utf8"
    )
    (output / "compromised_pair_telemetry.json").write_text(
        json.dumps(compromised, indent=2), encoding="utf8"
    )

    public_key_sha256 = hashlib.sha256(
        public_key_path.read_bytes()
    ).hexdigest()
    manifest_sha256 = hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    provenance = {
        "stage": 27,
        "seed": seed,
        "attestation_signature_verified": True,
        "attestation_algorithm": "Ed25519",
        "authority_private_key_available_to_verifier": False,
        "authority_private_key_uploaded": False,
        "manifest_sha256": manifest_sha256,
        "public_key_sha256": public_key_sha256,
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
        "STAGE27_ATTESTATION_VERIFY_OK "
        f"seed={seed} manifest_sha256={manifest_sha256} "
        f"public_key_sha256={public_key_sha256}",
        flush=True,
    )


if __name__ == "__main__":
    main()
