"""Stage 35 policy: transition-race, external freshness anchor and availability."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .stage27_authority import sha256_file

SCHEMA = "stage35-persistent-transition-adversarial-policy-v1"


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def build_policy(root: Path) -> dict:
    measured = [
        "live/stage34-nnrf-handler.c",
        "stage34/external_testbed/collector_service.py",
        "stage34/external_testbed/nrf.yaml",
        "stage34/external_testbed/scp.yaml",
        "stage34/external_testbed/nssf1.yaml",
        "stage34/external_testbed/nssf2.yaml",
        "stage35/external_testbed/Dockerfile",
        "stage35/external_testbed/collector_service.py",
        "stage35/transition_verifier_service.py",
        "stage35/state_anchor_service.py",
    ]
    measurements = {path: sha256_file(root / path) for path in measured}

    return {
        "stage": 35,
        "schema": SCHEMA,
        "open5gs_ref": "v2.7.6",
        "frozen_from_stage34": {
            "native_relational_mutation_hook": True,
            "relational_projection": True,
            "detector_rule": (
                "observed identity-bound projection differs from every "
                "authorized reference state for the current phase"
            ),
        },
        "legitimate_transitions": [
            "nssf2 graceful stop",
            "nssf2 start",
            "nssf1 restart",
        ],
        "transition_reference_model": (
            "for each transition phase the verifier accepts either the stable "
            "old endpoint state or the stable new endpoint state; all other "
            "relational states alert"
        ),
        "transition_attack_ticks": [
            5, 6, 8, 10,
            13, 14, 16, 18,
            21, 22, 24, 26,
        ],
        "transition_attack_families": [
            "endpoint_substitution",
            "service_injection",
            "identity_replacement",
        ],
        "freshness": {
            "collector_sequence": "strictly increasing",
            "challenge_nonce": "fresh per run",
            "state_location": "separate external anchor process",
            "cross_instance_replay_test": (
                "verifier A accepts; verifier B must reject same signed package "
                "through shared external anchor state"
            ),
            "limitation": (
                "anchor state is process-memory on free Render and is not "
                "crash-durable across anchor restart"
            ),
        },
        "authentication": {
            "collector_to_verifier": "external bearer token",
            "verifier_to_anchor": "separate external bearer token",
            "unauthenticated_negative_control": True,
        },
        "clean_soak_ticks_per_run": 300,
        "performance": {
            "full_path_benchmark_requests": 100,
            "latency_quantiles": ["p50", "p95", "p99"],
            "availability": "successful full verifier+anchor responses / requests",
            "throughput": "sequential full-path requests per second",
        },
        "heldout": {
            "seeds": [13001, 13016],
            "run_count": 16,
            "transition_attack_episodes_per_run": 12,
            "total_transition_attack_episodes": 192,
        },
        "blind_protocol": (
            "external verifier receives signed telemetry package only; private "
            "transition attack labels remain in a separate collector response "
            "and are joined by GitHub only after signed verdict completion"
        ),
        "measurements_sha256": measurements,
        "claim_scope": (
            "software-separated external testbed/collector, two verifier "
            "instances, and verifier-independent freshness anchor; not "
            "TPM/TEE/HSM and not provider-independent"
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="stage35_policy")
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
        "STAGE35_POLICY_OK "
        f"sha256={digest} measurements={len(policy['measurements_sha256'])}",
        flush=True,
    )


if __name__ == "__main__":
    main()
