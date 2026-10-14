"""Stage 27 blind detector with a third signed trust domain.

The blind job receives:
- label-free compromised NRF + compromised NF-witness telemetry;
- a public attestation bundle: canonical manifest, Ed25519 public key, signature.

It never receives the attestation private key or attack labels.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from .h2_wire import encode
from .stage20_structure import serialize_counter, structural_counter
from .stage21_semantic import semantic_projection, serialize_projection
from .stage25_live_detect import detect as stage25_detect
from .stage27_attestation_authority import SCHEMA


def verify_attestation_bundle(bundle_root: Path) -> dict:
    manifest_path = bundle_root / "manifest.json"
    public_key = bundle_root / "public_key.pem"
    signature = bundle_root / "signature.bin"
    provenance_path = bundle_root / "provenance.json"

    for path in (manifest_path, public_key, signature, provenance_path):
        if not path.exists():
            raise FileNotFoundError(f"Missing Stage27 attestation artifact: {path}")

    proc = subprocess.run(
        [
            "openssl", "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey", str(public_key),
            "-sigfile", str(signature),
            "-in", str(manifest_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise ValueError(
            "Stage27 attestation signature verification failed: "
            + proc.stderr.decode(errors="replace")[-500:]
        )

    manifest = json.loads(manifest_path.read_text(encoding="utf8"))
    provenance = json.loads(provenance_path.read_text(encoding="utf8"))
    if manifest.get("schema") != SCHEMA or provenance.get("schema") != SCHEMA:
        raise ValueError("Stage27 attestation schema mismatch")
    if provenance.get("private_key_exported") is not False:
        raise ValueError("Stage27 authority provenance indicates private-key export")

    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    public_key_sha256 = hashlib.sha256(public_key.read_bytes()).hexdigest()
    if manifest_sha256 != provenance.get("manifest_sha256"):
        raise ValueError("Stage27 manifest digest mismatch")
    if public_key_sha256 != provenance.get("public_key_sha256"):
        raise ValueError("Stage27 public-key digest mismatch")

    return {
        "manifest": manifest,
        "manifest_sha256": manifest_sha256,
        "public_key_sha256": public_key_sha256,
        "authority_provenance": provenance,
    }


def projection_fields(projection: dict) -> dict:
    instances = projection.get("nfInstances")
    if not isinstance(instances, list):
        raise ValueError("Stage27 projection lacks nfInstances")
    encoded = encode(projection)
    return {
        "status": 200,
        "canonical_bytes": len(encoded),
        "nssf_profiles": len(instances),
        "wire_bytes": len(encoded),
        "structure": serialize_counter(structural_counter(projection)),
        "semantic": serialize_projection(semantic_projection(projection)),
    }


def manifest_projection(manifest: dict) -> dict:
    profiles = manifest.get("expected_profiles")
    if not isinstance(profiles, list) or len(profiles) != 2:
        raise ValueError("Stage27 manifest must contain two expected NSSF profiles")

    projection = {"nfInstances": []}
    for index, item in enumerate(profiles):
        expected_slot = f"nssf-{index + 1}"
        if (
            not isinstance(item, dict)
            or item.get("slot") != expected_slot
            or item.get("nfType") != "NSSF"
            or item.get("nfStatus") != "REGISTERED"
        ):
            raise ValueError("Stage27 manifest expected profile contract invalid")
        projection["nfInstances"].append(
            {
                "slot": expected_slot,
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
            }
        )
    return projection


def detector_row(
    *,
    seed: int,
    tick: int,
    trusted_projection: dict,
    consumer_projection: dict,
    reference_scope: str,
) -> dict:
    trusted = projection_fields(trusted_projection)
    consumer = projection_fields(consumer_projection)
    return {
        "seed": seed,
        "tick": tick,
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
        "reference_scope": reference_scope,
    }


def detect(rows: list[dict], bundle_root: Path) -> dict:
    if not rows:
        raise ValueError("Stage27 telemetry is empty")

    attestation = verify_attestation_bundle(bundle_root)
    signed_projection = manifest_projection(attestation["manifest"])

    seed = int(rows[0]["seed"])
    attested_rows = []
    compromised_pair_rows = []

    for item in rows:
        if int(item["seed"]) != seed:
            raise ValueError("Stage27 telemetry mixes seeds")
        tick = int(item["tick"])
        consumer = item["consumer_projection"]
        witness = item["compromised_witness_projection"]

        if witness != consumer or not item.get("pairwise_false_state_exact"):
            raise ValueError(
                "Stage27 compromised pair is not a coordinated exact false state"
            )

        attested_rows.append(
            detector_row(
                seed=seed,
                tick=tick,
                trusted_projection=signed_projection,
                consumer_projection=consumer,
                reference_scope="signed_software_attestation_domain",
            )
        )
        compromised_pair_rows.append(
            detector_row(
                seed=seed,
                tick=tick,
                trusted_projection=witness,
                consumer_projection=consumer,
                reference_scope="compromised_nrf_plus_compromised_nf_witness",
            )
        )

    frozen = stage25_detect(attested_rows, compromised_pair_rows)

    return {
        "seed": seed,
        "protocol": {
            "private_labels_received": False,
            "attestation_private_key_received": False,
            "detector_retuned_for_stage27": False,
            "attestation_signature_verified": True,
            "attestation_schema": SCHEMA,
            "manifest_sha256": attestation["manifest_sha256"],
            "public_key_sha256": attestation["public_key_sha256"],
            "authority_claim_scope": attestation[
                "authority_provenance"
            ]["claim_scope"],
            "pairwise_compromised_reference_scope": (
                "coordinated NRF + NF-side witness false state"
            ),
            "third_reference_scope": (
                "signed deployment-state contract from isolated "
                "GitHub Actions authority job"
            ),
        },
        "attested_channel_calibration": frozen["external_channel_calibration"],
        "compromised_pair_channel_calibration": frozen[
            "common_channel_calibration"
        ],
        "attested_reference": frozen["external_reference"],
        "compromised_pair": frozen["common_path_control"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--telemetry", required=True)
    parser.add_argument("--attestation-bundle", required=True)
    parser.add_argument("--output", default="stage27_detector")
    args = parser.parse_args()

    rows = json.loads(Path(args.telemetry).read_text(encoding="utf8"))
    result = detect(rows, Path(args.attestation_bundle))

    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    (root / "alarms.json").write_text(
        json.dumps(result, indent=2), encoding="utf8"
    )

    attested_count = sum(
        bool(row["stage21_combined_alert"])
        for row in result["attested_reference"]["ticks"]
    )
    pair_count = sum(
        bool(row["stage21_combined_alert"])
        for row in result["compromised_pair"]["ticks"]
    )
    print(
        "STAGE27_BLIND_DETECT_OK "
        f"seed={result['seed']} "
        f"attested_alarms={attested_count} "
        f"compromised_pair_alarms={pair_count} "
        "signature_verified=true",
        flush=True,
    )


if __name__ == "__main__":
    main()
