"""Frozen Stage 37 randomized-topology policy manifest."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

POLICY = {
    "stage": 37,
    "schema": "stage37-randomized-topology-policy-v1",
    "open5gs_ref": "v2.7.6",
    "slots": {
        "nssf1": "127.0.0.12",
        "nssf2": "127.0.0.13",
    },
    "scenario_generator": {
        "topology_templates": 4,
        "orders": ["stop-start-restart", "restart-stop-start"],
        "transition_duration_ticks": [8, 14],
        "density_bins": {
            "low": [0.20, 0.35],
            "medium": [0.40, 0.55],
            "high": [0.60, 0.80],
        },
        "mutation_families": [
            "identity_replacement",
            "endpoint_substitution",
            "service_injection",
            "fqdn_substitution",
        ],
        "mutation_variants_per_family": 4,
        "attack_target": "stable_nssf_slot_during_each_transition",
        "private_schedule_entropy": "seed+challenge_nonce+collector_secret",
    },
    "verifier": {
        "stable_slot": "exact_identity_and_relational_attributes",
        "transitioning_slot": "may_be_absent_or_match_authorized_pre/post_attributes",
        "private_attack_labels_received": False,
        "legacy_comparator": "phase_aware_profile_count_and_registered_count",
    },
    "trust_controls": {
        "collector_signature": "ECDSA-P256-SHA256",
        "verifier_signature": "ECDSA-P256-SHA256",
        "collector_to_verifier": "bearer",
        "verifier_to_anchor": "bearer",
        "freshness": "external_shared_anchor",
    },
}


def canonical_bytes(doc) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="stage37_policy")
    args = parser.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    data = canonical_bytes(POLICY)
    digest = hashlib.sha256(data).hexdigest()
    (out / "policy.json").write_bytes(data + b"\n")
    (out / "policy.sha256").write_text(digest + "\n", encoding="ascii")
    print(digest)


if __name__ == "__main__":
    main()
