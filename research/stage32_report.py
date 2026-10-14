"""Stage 32 post-hoc audit for the external KMS/HSM-backed root."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from .stage30_report import load_by_seed
from .stage31_report import (
    evaluate_seed as stage31_evaluate_seed,
    summarize as stage31_summarize,
)

EXPECTED_SEEDS = tuple(range(9901, 9909))


def evaluate_seed(labels, alarms, capture, attest):
    seed = int(labels["seed"])
    if any(int(doc["seed"]) != seed for doc in (alarms, capture, attest)):
        raise AssertionError("Stage32 seed mismatch")
    required = (
        int(labels["stage"]) == 32
        and int(capture["stage"]) == 32
        and int(attest["stage"]) == 32
        and labels["stage32_role"] == "held_out_external_kms_root_validation"
        and capture["stage32_role"] == "held_out_external_kms_root_validation"
        and capture["stage31_bundle_provenance_frozen"]
        and capture["stage30_freshness_protocol_frozen"]
        and capture["stage29_detector_rule_frozen"]
        and attest["external_root_verified"]
        and attest["external_root_provider"] == "AWS KMS"
        and attest["external_private_key_available_to_github"] is False
        and attest["external_approval_mutable_by_github_role"] is False
        and attest["github_artifact_attestation_verified"]
        and attest["github_tampered_bundle_rejected"]
        and attest["stale_replay_accepted"] == 0
        and alarms["protocol"].get("detector_retuned_for_stage32") is False
    )
    if not required:
        raise AssertionError("Stage32 trust/provenance audit failed")

    l = copy.deepcopy(labels)
    c = copy.deepcopy(capture)
    a = copy.deepcopy(attest)
    l["stage"] = 31
    c["stage"] = 31
    a["stage"] = 31
    l["stage31_role"] = "held_out_github_attestation_validation"
    c["stage31_role"] = "held_out_github_attestation_validation"
    c["stage30_freshness_protocol_frozen"] = True
    c["stage29_detector_rule_frozen"] = True

    row = stage31_evaluate_seed(l, alarms, c, a)
    row.update(
        {
            "external_root_key_arn": attest["external_root_key_arn"],
            "external_root_public_key_sha256": attest[
                "external_root_public_key_sha256"
            ],
            "external_policy_sha256": attest["external_policy_sha256"],
        }
    )
    return row


def summarize(rows):
    summary = stage31_summarize(rows)
    keys = {row["external_root_key_arn"] for row in rows}
    pubs = {row["external_root_public_key_sha256"] for row in rows}
    policies = {row["external_policy_sha256"] for row in rows}
    if len(keys) != 1 or len(pubs) != 1 or len(policies) != 1:
        raise AssertionError(
            "Stage32 runners did not share one external root/policy"
        )
    summary.update(
        {
            "external_root_key_arn": next(iter(keys)),
            "external_root_public_key_sha256": next(iter(pubs)),
            "external_policy_sha256": next(iter(policies)),
            "external_root_verified_runners": len(rows),
        }
    )
    return summary


def markdown(summary):
    ext = summary["external_reference"]
    aug = ext["augmented"]
    legacy = ext["legacy_combined"]
    return "\n".join(
        [
            "# Stage 32 — external KMS/HSM-backed root of trust",
            "",
            (
                f"Independent Open5GS runners: "
                f"**{summary['independent_live_runners']}**; "
                f"attack episodes: **{summary['total_randomized_attack_episodes']}**."
            ),
            (
                "External root verification succeeded on "
                f"**{summary['external_root_verified_runners']}/"
                f"{summary['independent_live_runners']}** runners."
            ),
            "",
            "| Detector | Attack recall | Wilson 95% | FA / 1000 clean | Transition FA / 1000 |",
            "|---|---:|---:|---:|---:|",
            (
                f"| Frozen Stage-21 combined | "
                f"{legacy['event_recall']:.3f} "
                f"({legacy['event_detected']}/{legacy['event_total']}) | "
                f"[{legacy['event_recall_wilson95'][0]:.3f}, "
                f"{legacy['event_recall_wilson95'][1]:.3f}] | "
                f"{legacy['false_alarms_per_1000_clean_ticks']:.3f} | "
                f"{legacy['legitimate_transition_fa_per_1000']:.3f} |"
            ),
            (
                f"| Stage-29 augmented | "
                f"{aug['event_recall']:.3f} "
                f"({aug['event_detected']}/{aug['event_total']}) | "
                f"[{aug['event_recall_wilson95'][0]:.3f}, "
                f"{aug['event_recall_wilson95'][1]:.3f}] | "
                f"{aug['false_alarms_per_1000_clean_ticks']:.3f} | "
                f"{aug['legitimate_transition_fa_per_1000']:.3f} |"
            ),
            "",
            f"External KMS key ARN: {summary['external_root_key_arn']}",
            (
                "External public-key SHA-256: "
                f"{summary['external_root_public_key_sha256']}"
            ),
            (
                "Externally approved policy SHA-256: "
                f"{summary['external_policy_sha256']}"
            ),
            "",
            (
                "Stale/replay baseline acceptance: "
                f"**{summary['stale_replay_accepted']}/"
                f"{summary['stale_replay_attempts']}**."
            ),
            (
                "Colluding NRF+witness augmented recall: "
                f"**{summary['compromised_pair']['augmented']['event_recall']:.3f}**."
            ),
            "",
            (
                "Stage 32 moves signing-key custody and the policy-approval "
                "decision outside GitHub Actions. The GitHub role can invoke "
                "the signer but cannot export the private key or change the "
                "externally administered approved digest."
            ),
            (
                "The verifier and detector still run on GitHub-hosted runners; "
                "therefore this is an external cryptographic root and approval "
                "boundary, not complete independence from a malicious GitHub "
                "verifier/control plane."
            ),
            "",
        ]
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage32_report")
    args = parser.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    alarms = load_by_seed(root, "alarms.json")
    capture = load_by_seed(root, "provenance.json")
    attest = load_by_seed(root, "attestation_provenance.json")

    expected = set(EXPECTED_SEEDS)
    if any(
        set(group) != expected
        for group in (labels, alarms, capture, attest)
    ):
        raise AssertionError(
            "Stage32 requires all eight held-out runners"
        )

    rows = [
        evaluate_seed(labels[s], alarms[s], capture[s], attest[s])
        for s in EXPECTED_SEEDS
    ]
    summary = summarize(rows)

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "seed_results.json").write_text(
        json.dumps(rows, indent=2), encoding="utf8"
    )
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf8"
    )
    report = markdown(summary)
    (output / "REPORT.md").write_text(report, encoding="utf8")
    print(report)


if __name__ == "__main__":
    main()
