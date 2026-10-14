"""Stage 32 deterministic externally approved policy bundle.

The bundle is intentionally independent of GitHub run identity. It contains only
reviewable experiment policy and source/configuration measurements so an external
KMS/HSM-side approval service can pin exactly one digest before GitHub requests a
signature.

The external signing service must refuse to sign any digest other than the
administrator-approved value stored outside GitHub.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .stage27_authority import sha256_file
from .stage30_authority import EPOCH_SPECS

SCHEMA = "stage32-external-kms-policy-v1"
SIGNING_ALGORITHM = "ECDSA_SHA_256"


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf8")


def build_policy(repo_root: Path) -> dict:
    measured = [
        "live/nssf.yaml",
        "live/nssf2.yaml",
        "live/stage28-nnrf-handler.c",
        "research/stage29_live_detect.py",
        "research/stage30_attestation.py",
        "research/stage30_live_detect.py",
        "research/stage31_attestation.py",
    ]
    measurements = {}
    for relative in measured:
        path = repo_root / relative
        if not path.is_file():
            raise FileNotFoundError(path)
        measurements[relative] = sha256_file(path)

    epochs = [
        {
            "epoch": int(spec["epoch"]),
            "valid_from_tick": int(spec["valid_from_tick"]),
            "valid_until_tick": int(spec["valid_until_tick"]),
            "expected_nssf_count": int(spec["expected_nssf_count"]),
            "expected_registered_count": int(spec["expected_registered_count"]),
            "transition": str(spec["transition"]),
        }
        for spec in EPOCH_SPECS
    ]

    return {
        "stage": 32,
        "schema": SCHEMA,
        "external_root_model": "aws_kms_asymmetric_nonexportable_key",
        "signing_algorithm": SIGNING_ALGORITHM,
        "approval_model": (
            "external signer compares SHA-256 policy digest with an "
            "administrator-managed allowlist value outside GitHub"
        ),
        "open5gs_ref": "v2.7.6",
        "detector_rule": (
            "Stage-29 verified attested-invariant OR frozen Stage-21 combined"
        ),
        "freshness_protocol": "Stage-30 monotonic signed logical epoch chain",
        "github_bundle_provenance": "Stage-31 GitHub Artifact Attestation",
        "epochs": epochs,
        "measurements_sha256": measurements,
        "claim_scope": (
            "external KMS/HSM-backed key custody and external digest approval; "
            "GitHub-hosted verifier still remains in the software trust base"
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="stage32_policy")
    args = parser.parse_args()

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    policy = build_policy(Path("."))
    payload = canonical_bytes(policy)
    digest = hashlib.sha256(payload).hexdigest()

    (output / "policy.json").write_bytes(payload)
    (output / "policy.pretty.json").write_text(
        json.dumps(policy, indent=2, ensure_ascii=False),
        encoding="utf8",
    )
    (output / "policy.sha256").write_text(digest + "\n", encoding="ascii")

    print(
        "STAGE32_POLICY_OK "
        f"sha256={digest} "
        f"measurements={len(policy['measurements_sha256'])}",
        flush=True,
    )


if __name__ == "__main__":
    main()
