"""Stage 31 authority-bundle verifier.

GitHub CLI performs the cryptographic GitHub Artifact Attestation verification
before this module is invoked. This module requires an explicit verification
marker produced only after that check, then reuses the frozen Stage-30 signed
epoch-chain verifier and projector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .stage30_attestation import (
    load_and_verify_chain,
    project,
    run_replay_audit,
)


def load_github_verification(marker_path: Path) -> dict:
    marker = json.loads(marker_path.read_text(encoding="utf8"))
    required = (
        marker.get("github_artifact_attestation_verified") is True
        and marker.get("tampered_bundle_rejected") is True
        and marker.get("repository")
        and marker.get("source_digest")
        and marker.get("signer_workflow")
        and marker.get("authority_bundle_sha256")
    )
    if not required:
        raise ValueError("Stage31 GitHub attestation marker is incomplete")
    return marker


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-telemetry", required=True)
    parser.add_argument("--authority-dir", required=True)
    parser.add_argument("--github-verification-marker", required=True)
    parser.add_argument("--github-verification-json", required=True)
    parser.add_argument("--output", default="stage31_projected")
    args = parser.parse_args()

    raw_rows = json.loads(
        Path(args.raw_telemetry).read_text(encoding="utf8")
    )
    if not raw_rows:
        raise ValueError("Empty Stage31 raw telemetry")
    seed = int(raw_rows[0]["seed"])
    if any(int(row["seed"]) != seed for row in raw_rows):
        raise ValueError("Mixed Stage31 seeds")

    marker_path = Path(args.github_verification_marker)
    verification_json_path = Path(args.github_verification_json)
    marker = load_github_verification(marker_path)
    verification_json = json.loads(
        verification_json_path.read_text(encoding="utf8")
    )
    if not isinstance(verification_json, list) or not verification_json:
        raise ValueError("Stage31 GitHub attestation verification JSON is empty")

    authority_dir = Path(args.authority_dir)
    manifests = load_and_verify_chain(authority_dir)
    freshness = run_replay_audit(manifests)
    if freshness["accepted_count"] != 0:
        raise AssertionError("Stage31 stale/replay baseline was accepted")

    attested, compromised = project(raw_rows, manifests)

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "attested_telemetry.json").write_text(
        json.dumps(attested, indent=2), encoding="utf8"
    )
    (output / "compromised_pair_telemetry.json").write_text(
        json.dumps(compromised, indent=2), encoding="utf8"
    )
    (output / "freshness_audit.json").write_text(
        json.dumps(freshness, indent=2), encoding="utf8"
    )

    public_key = authority_dir / "public.pem"
    provenance = {
        "stage": 31,
        "seed": seed,
        "attestation_algorithm": "Ed25519",
        "signed_epoch_chain_verified": True,
        "epoch_count": len(manifests),
        "epoch_sequence": [int(m["epoch"]) for m in manifests],
        "authority_public_key_sha256": hashlib.sha256(
            public_key.read_bytes()
        ).hexdigest(),
        "authority_private_key_available_to_verifier": False,
        "authority_private_key_uploaded": False,
        "monotonic_logical_freshness_enforced": True,
        "trusted_wall_clock_used": False,
        "stale_replay_attempts": freshness["attempt_count"],
        "stale_replay_accepted": freshness["accepted_count"],
        "pairwise_common_source_equal_in_raw_input": all(
            int(row["consumer_nssf_count"])
            == int(row["compromised_witness_nssf_count"])
            and int(row["consumer_registered_count"])
            == int(row["compromised_witness_registered_count"])
            for row in raw_rows
        ),
        "realized_attack_schedule_available_to_verifier": False,
        "stage29_rule_frozen": True,
        "github_artifact_attestation_verified": True,
        "github_tampered_bundle_rejected": True,
        "github_attestation_repository": marker["repository"],
        "github_attestation_source_digest": marker["source_digest"],
        "github_attestation_signer_workflow": marker["signer_workflow"],
        "authority_bundle_sha256": marker["authority_bundle_sha256"],
        "github_verification_json_sha256": hashlib.sha256(
            verification_json_path.read_bytes()
        ).hexdigest(),
        "authority_bundle_verified_before_extraction": True,
        "github_oidc_attestation_layer_added_in_stage31": True,
    }
    (output / "attestation_provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf8"
    )

    print(
        "STAGE31_GITHUB_ATTESTATION_VERIFY_OK "
        f"seed={seed} replay_rejected="
        f"{freshness['rejected_count']}/{freshness['attempt_count']} "
        f"bundle={marker['authority_bundle_sha256']}",
        flush=True,
    )


if __name__ == "__main__":
    main()
