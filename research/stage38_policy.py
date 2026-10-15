"""Stage 38 multi-NF / independent-witness policy manifest."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

POLICY = {
    "stage": 38,
    "schema": "stage38-multi-nf-witness-policy-v1",
    "open5gs_ref": "v2.7.6",
    "nf_types": ["NSSF", "AUSF", "BSF", "UDM"],
    "slots": {
        "nssf1": {"type": "NSSF", "endpoint": "127.0.0.12"},
        "nssf2": {"type": "NSSF", "endpoint": "127.0.0.13"},
        "ausf1": {"type": "AUSF", "endpoint": "127.0.0.14"},
        "ausf2": {"type": "AUSF", "endpoint": "127.0.0.15"},
        "bsf1": {"type": "BSF", "endpoint": "127.0.0.16"},
        "bsf2": {"type": "BSF", "endpoint": "127.0.0.17"},
        "udm1": {"type": "UDM", "endpoint": "127.0.0.18"},
        "udm2": {"type": "UDM", "endpoint": "127.0.0.19"},
    },
    "scenario_generator": {
        "topology_templates": 8,
        "transition_duration_ticks": [6, 10],
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
            "nf_type_substitution",
            "compound_identity_service",
        ],
        "mutation_variants_per_family": 4,
        "compound_ticks": "0_or_2_independent_nf_types",
        "private_schedule_entropy": "seed+challenge_nonce+collector_secret",
    },
    "witness": {
        "source": "nf_runtime_uuid+proc_cmdline+direct_sbi_socket",
        "nrf_discovery_used": False,
        "signed": True,
        "required_for_reference_acceptance": True,
        "attested_fields": [
            "slot", "nf_type", "endpoint", "nf_instance_id",
            "process_alive", "direct_sbi_tcp_reachable",
        ],
    },
    "verifier": {
        "private_attack_labels_received": False,
        "stable_slots": "exact_reference_and_witness_binding",
        "moving_slot": "authorized_pre_or_post_reference_and_witness_state",
        "legacy_comparator": "per-type profile count and REGISTERED count",
    },
    "trust_controls": {
        "collector_signature": "ECDSA-P256-SHA256",
        "witness_signature": "ECDSA-P256-SHA256",
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
    p = argparse.ArgumentParser()
    p.add_argument("--output", default="stage38_policy")
    args = p.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    data = canonical_bytes(POLICY)
    digest = hashlib.sha256(data).hexdigest()
    (out / "policy.json").write_bytes(data + b"\n")
    (out / "policy.sha256").write_text(digest + "\n", encoding="ascii")
    print(digest)


if __name__ == "__main__":
    main()
