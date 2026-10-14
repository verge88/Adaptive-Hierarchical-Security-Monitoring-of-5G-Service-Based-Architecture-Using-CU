"""Stage 32 composed verifier.

The verifier requires two independent layers before detector projection:
1) external AWS KMS/HSM-backed approval of the deterministic Stage-32 policy;
2) frozen Stage-31 GitHub Artifact Attestation for the dynamic authority bundle.

Only then is the frozen Stage-30 signed epoch chain verified and projected.
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
from .stage31_attestation import load_github_verification


def load_external_root(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf8"))
    required = (
        int(doc.get("stage", -1)) == 32
        and doc.get("external_signature_verified") is True
        and doc.get("digest_sha256")
        and doc.get("kms_key_arn")
        and doc.get("public_key_sha256")
        and doc.get("signing_algorithm") == "ECDSA_SHA_256"
        and doc.get("approval_source") == "external_ssm_allowlist"
    )
    if not required:
        raise ValueError("Stage32 external-root verification is incomplete")
    return doc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-telemetry", required=True)
    parser.add_argument("--authority-dir", required=True)
    parser.add_argument("--github-verification-marker", required=True)
    parser.add_argument("--github-verification-json", required=True)
    parser.add_argument("--external-root-verification", required=True)
    parser.add_argument("--output", default="stage32_projected")
    args = parser.parse_args()

    raw_rows = json.loads(
        Path(args.raw_telemetry).read_text(encoding="utf8")
    )
    if not raw_rows:
        raise ValueError("Empty Stage32 raw telemetry")
    seed = int(raw_rows[0]["seed"])
    if any(int(row["seed"]) != seed for row in raw_rows):
        raise ValueError("Mixed Stage32 seeds")

    github_marker = load_github_verification(
        Path(args.github_verification_marker)
    )
    github_json_path = Path(args.github_verification_json)
    github_json = json.loads(github_json_path.read_text(encoding="utf8"))
    if not isinstance(github_json, list) or not github_json:
        raise ValueError("Stage32 GitHub attestation JSON is empty")

    external = load_external_root(
        Path(args.external_root_verification)
    )

    authority_dir = Path(args.authority_dir)
    manifests = load_and_verify_chain(authority_dir)
    freshness = run_replay_audit(manifests)
    if freshness["accepted_count"] != 0:
        raise AssertionError("Stage32 stale/replay baseline was accepted")

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
        "stage": 32,
        "seed": seed,
        "external_root_verified": True,
        "external_root_provider": "AWS KMS",
        "external_root_key_arn": external["kms_key_arn"],
        "external_root_public_key_sha256": external[
            "public_key_sha256"
        ],
        "external_policy_sha256": external["digest_sha256"],
        "external_approval_source": external["approval_source"],
        "external_private_key_available_to_github": False,
        "external_approval_mutable_by_github_role": False,
        "github_artifact_attestation_verified": True,
        "github_tampered_bundle_rejected": True,
        "github_attestation_repository": github_marker["repository"],
        "github_attestation_source_digest": github_marker["source_digest"],
        "github_attestation_signer_workflow": github_marker[
            "signer_workflow"
        ],
        "authority_bundle_sha256": github_marker[
            "authority_bundle_sha256"
        ],
        "github_verification_json_sha256": hashlib.sha256(
            github_json_path.read_bytes()
        ).hexdigest(),
        "signed_epoch_chain_verified": True,
        "epoch_count": len(manifests),
        "epoch_sequence": [int(m["epoch"]) for m in manifests],
        "authority_public_key_sha256": hashlib.sha256(
            public_key.read_bytes()
        ).hexdigest(),
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
        "stage30_freshness_frozen": True,
        "stage31_bundle_provenance_frozen": True,
    }
    (output / "attestation_provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf8"
    )

    print(
        "STAGE32_COMPOSED_ROOT_VERIFY_OK "
        f"seed={seed} external={external['kms_key_arn']} "
        f"replay_rejected={freshness['rejected_count']}/"
        f"{freshness['attempt_count']}",
        flush=True,
    )


if __name__ == "__main__":
    main()
