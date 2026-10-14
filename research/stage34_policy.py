"""Stage 34 deterministic policy for external relational collection."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .stage27_authority import sha256_file

SCHEMA = "stage34-external-relational-policy-v1"


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def build_policy(root: Path) -> dict:
    measured = [
        "live/stage34-nnrf-handler.c",
        "stage34/external_testbed/Dockerfile",
        "stage34/external_testbed/collector_service.py",
        "stage34/external_testbed/nrf.yaml",
        "stage34/external_testbed/scp.yaml",
        "stage34/external_testbed/nssf1.yaml",
        "stage34/external_testbed/nssf2.yaml",
        "stage34/relational_verifier_service.py",
    ]
    hashes = {path: sha256_file(root / path) for path in measured}

    return {
        "stage": 34,
        "schema": SCHEMA,
        "open5gs_ref": "v2.7.6",
        "external_testbed": (
            "Open5GS NRF/SCP/two NSSF processes run inside external Render "
            "collector container; GitHub does not create telemetry rows"
        ),
        "collector_signature": "ECDSA P-256 over canonical telemetry package",
        "verifier_signature": "ECDSA P-256 over canonical relational verdict",
        "freshness": {
            "challenge_nonce": "unique per run",
            "collector_sequence": "strictly increasing within service process",
            "verifier_replay_cache": "process-lifetime nonce set",
        },
        "baseline": {
            "source": "external collector clean pre-attack Open5GS observations",
            "stable_samples": 12,
            "required_nssf_count": 2,
            "required_registered_count": 2,
        },
        "relational_projection": [
            "nfInstanceId as dictionary key",
            "nfType",
            "nfStatus",
            "fqdn",
            "ipv4Addresses",
            "nfServices.serviceInstanceId",
            "nfServices.serviceName",
            "nfServices.scheme",
            "nfServices.nfServiceStatus",
            "nfServices.versions",
            "nfServices.ipEndPoints",
            "duplicate nfInstanceId detection",
        ],
        "attack_families": [
            "identity_swap",
            "identity_replacement",
            "endpoint_substitution",
            "service_injection",
        ],
        "attack_property": (
            "all mutation families preserve NSSF profile count and REGISTERED "
            "profile count; legacy count/status invariant must remain silent"
        ),
        "episodes_per_run": 24,
        "duration_bins": {
            "short": [2, 4],
            "medium": [5, 8],
            "long": [9, 14],
        },
        "density_bins": {
            "low": [0.25, 0.40],
            "medium": [0.45, 0.70],
            "high": [0.75, 1.00],
        },
        "blind_protocol": (
            "private labels returned separately by collector and never sent "
            "to relational verifier; labels joined only after signed verdict"
        ),
        "measurements_sha256": hashes,
        "claim_scope": (
            "external software-separated testbed/collector and relational "
            "verifier; no TPM/TEE measurement of Render hosts"
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="stage34_policy")
    args = parser.parse_args()

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    policy = build_policy(Path("."))
    raw = canonical_bytes(policy)
    digest = hashlib.sha256(raw).hexdigest()

    (output / "policy.json").write_bytes(raw)
    (output / "policy.pretty.json").write_text(
        json.dumps(policy, indent=2, ensure_ascii=False), encoding="utf8"
    )
    (output / "policy.sha256").write_text(digest + "\n", encoding="ascii")
    print(
        f"STAGE34_POLICY_OK sha256={digest} "
        f"measurements={len(policy['measurements_sha256'])}",
        flush=True,
    )


if __name__ == "__main__":
    main()
