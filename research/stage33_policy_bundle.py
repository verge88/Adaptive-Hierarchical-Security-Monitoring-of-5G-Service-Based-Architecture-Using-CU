"""Stage 33 deterministic policy for an externally executed verifier.

The policy is reviewed and approved outside GitHub, then signed by the Stage-32
external KMS root. It binds the baseline epochs and the exact security-sensitive
code that an external verifier is expected to execute.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .stage27_authority import sha256_file
from .stage30_authority import EPOCH_SPECS

SCHEMA = "stage33-external-verifier-policy-v1"
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
        "research/h2_wire.py",
        "research/stage15_detector.py",
        "research/stage18_detect.py",
        "research/stage19_detector.py",
        "research/stage19_live_detect.py",
        "research/stage20_structure.py",
        "research/stage20_live_detect.py",
        "research/stage21_semantic.py",
        "research/stage21_live_detect.py",
        "research/stage25_live_detect.py",
        "research/stage27_attestation.py",
        "research/stage27_live_detect.py",
        "research/stage29_live_detect.py",
        "research/stage33_external_verifier.py",
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
            "expected_registered_count": int(
                spec["expected_registered_count"]
            ),
            "transition": str(spec["transition"]),
        }
        for spec in EPOCH_SPECS
    ]

    return {
        "stage": 33,
        "schema": SCHEMA,
        "open5gs_ref": "v2.7.6",
        "external_root_model": "stage32_aws_kms_nonexportable_key",
        "external_execution_model": (
            "independently administered HTTP verifier outside GitHub Actions"
        ),
        "signing_algorithm": SIGNING_ALGORITHM,
        "detector_rule": (
            "Stage-29 verified attested-invariant OR frozen Stage-21 combined"
        ),
        "epochs": epochs,
        "measurements_sha256": measurements,
        "input_contract": (
            "label-free raw telemetry only; no realized private attack schedule"
        ),
        "output_contract": (
            "canonical signed verdict containing per-tick frozen detector alarms"
        ),
        "claim_scope": (
            "detector projection and decision executed outside GitHub; capture "
            "and final statistical audit remain GitHub-hosted"
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="stage33_policy")
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
        "STAGE33_POLICY_OK "
        f"sha256={digest} "
        f"measurements={len(policy['measurements_sha256'])}",
        flush=True,
    )


if __name__ == "__main__":
    main()
