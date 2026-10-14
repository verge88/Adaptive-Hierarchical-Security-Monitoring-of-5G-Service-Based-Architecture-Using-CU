"""Stage 31 audit: GitHub-anchored authority-bundle provenance."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from .stage30_report import (
    EXPECTED_SEEDS as STAGE30_EXPECTED_SEEDS,
    evaluate_seed as stage30_evaluate_seed,
    load_by_seed,
    summarize as stage30_summarize,
)

EXPECTED_SEEDS = tuple(range(9801, 9809))


def evaluate_seed(labels: dict, alarms: dict, capture: dict, attest: dict) -> dict:
    seed = int(labels["seed"])
    if any(int(doc["seed"]) != seed for doc in (alarms, capture, attest)):
        raise AssertionError("Stage31 seed mismatch")
    if int(labels["stage"]) != 31 or int(capture["stage"]) != 31:
        raise AssertionError("Stage31 capture stage mismatch")
    if int(attest["stage"]) != 31:
        raise AssertionError("Stage31 attestation stage mismatch")

    protocol = alarms.get("protocol", {})
    required = (
        labels["stage31_role"] == "held_out_github_attestation_validation"
        and capture["stage31_role"] == "held_out_github_attestation_validation"
        and capture["stage30_freshness_protocol_frozen"]
        and capture["stage29_detector_rule_frozen"]
        and attest["github_artifact_attestation_verified"]
        and attest["github_tampered_bundle_rejected"]
        and attest["authority_bundle_verified_before_extraction"]
        and attest["github_oidc_attestation_layer_added_in_stage31"]
        and attest["github_attestation_repository"]
        and attest["github_attestation_source_digest"]
        and attest["github_attestation_signer_workflow"]
        and protocol.get("detector_retuned_for_stage31") is False
        and protocol.get("stage29_rule_frozen_for_stage31")
        and protocol.get("stage30_freshness_protocol_frozen_for_stage31")
        and protocol.get("stage31_private_attack_schedule_received") is False
    )
    if not required:
        raise AssertionError("Stage31 provenance audit failed")

    # Reuse the already-audited Stage-30 statistical evaluator. Only the stage
    # markers differ; the live-transition, attack and freshness protocol is
    # deliberately frozen.
    l30 = copy.deepcopy(labels)
    c30 = copy.deepcopy(capture)
    a30 = copy.deepcopy(attest)
    l30["stage"] = 30
    c30["stage"] = 30
    a30["stage"] = 30
    row = stage30_evaluate_seed(l30, alarms, c30, a30)

    row["github_artifact_attestation_verified"] = True
    row["github_tampered_bundle_rejected"] = True
    row["authority_bundle_sha256"] = attest["authority_bundle_sha256"]
    row["github_attestation_repository"] = attest[
        "github_attestation_repository"
    ]
    row["github_attestation_source_digest"] = attest[
        "github_attestation_source_digest"
    ]
    row["github_attestation_signer_workflow"] = attest[
        "github_attestation_signer_workflow"
    ]
    row["github_verification_json_sha256"] = attest[
        "github_verification_json_sha256"
    ]
    return row


def summarize(rows: list[dict]) -> dict:
    summary = stage30_summarize(rows)

    bundles = {row["authority_bundle_sha256"] for row in rows}
    repositories = {row["github_attestation_repository"] for row in rows}
    source_digests = {
        row["github_attestation_source_digest"] for row in rows
    }
    signer_workflows = {
        row["github_attestation_signer_workflow"] for row in rows
    }
    verify_hashes = {
        row["github_verification_json_sha256"] for row in rows
    }

    if len(bundles) != 1:
        raise AssertionError("Stage31 runners verified different authority bundles")
    if len(repositories) != 1:
        raise AssertionError("Stage31 repository identity differs across runners")
    if len(source_digests) != 1:
        raise AssertionError("Stage31 source digest differs across runners")
    if len(signer_workflows) != 1:
        raise AssertionError("Stage31 signer workflow differs across runners")

    summary.update(
        {
            "github_attestation_verified_runners": sum(
                int(row["github_artifact_attestation_verified"])
                for row in rows
            ),
            "tampered_bundle_rejected_runners": sum(
                int(row["github_tampered_bundle_rejected"])
                for row in rows
            ),
            "authority_bundle_sha256": next(iter(bundles)),
            "github_attestation_repository": next(iter(repositories)),
            "github_attestation_source_digest": next(iter(source_digests)),
            "github_attestation_signer_workflow": next(iter(signer_workflows)),
            "verification_output_unique_count": len(verify_hashes),
        }
    )
    return summary


def markdown(summary: dict) -> str:
    ext = summary["external_reference"]
    pair = summary["compromised_pair"]
    gain = summary["heldout_gain_over_legacy"]
    aug = ext["augmented"]
    transition_ci = aug["legitimate_transition_zero_fa_wilson95"]
    replay_ci = summary["stale_replay_acceptance_wilson95"]

    lines = [
        "# Stage 31 — GitHub-anchored authority-bundle provenance",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"attack episodes: **{summary['total_randomized_attack_episodes']}**; "
            f"unique private plans: **{summary['unique_private_plan_count']}**."
        ),
        (
            "GitHub Artifact Attestation verification succeeded on "
            f"**{summary['github_attestation_verified_runners']}/"
            f"{summary['independent_live_runners']}** verifier jobs; "
            "tampered authority bundles were rejected on "
            f"**{summary['tampered_bundle_rejected_runners']}/"
            f"{summary['independent_live_runners']}** jobs."
        ),
        "",
        "| Detector | Attack recall | Wilson 95% | Delay | Mutation coverage | FA / 1000 clean | Transition FA / 1000 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]

    for name, label in (
        ("legacy_combined", "Frozen Stage-21 combined"),
        ("attested_invariant", "Stage-29 invariant"),
        ("augmented", "Stage-29 augmented"),
    ):
        row = ext[name]
        ci = row["event_recall_wilson95"]
        lines.append(
            f"| {label} | {row['event_recall']:.3f} "
            f"({row['event_detected']}/{row['event_total']}) | "
            f"[{ci[0]:.3f}, {ci[1]:.3f}] | "
            f"{row['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{row['mutation_tick_alert_coverage']:.3f} | "
            f"{row['false_alarms_per_1000_clean_ticks']:.3f} | "
            f"{row['legitimate_transition_fa_per_1000']:.3f} |"
        )

    lines.extend(
        [
            "",
            (
                "Held-out augmented recall gain over frozen legacy: "
                f"**{gain['runner_mean_difference']:+.3f}**, "
                "95% runner-cluster bootstrap CI "
                f"[{gain['runner_cluster_bootstrap_ci95'][0]:+.3f}, "
                f"{gain['runner_cluster_bootstrap_ci95'][1]:+.3f}]."
            ),
            (
                "Legitimate-transition alerts: "
                f"**{aug['legitimate_transition_alert_count']}/"
                f"{aug['legitimate_transition_tick_count']}**, "
                "Wilson 95% "
                f"[{transition_ci[0]:.3f}, {transition_ci[1]:.3f}]."
            ),
            (
                "Stale/replay baseline acceptance: "
                f"**{summary['stale_replay_accepted']}/"
                f"{summary['stale_replay_attempts']}**, "
                "Wilson 95% "
                f"[{replay_ci[0]:.3f}, {replay_ci[1]:.3f}]."
            ),
            (
                "Colluding NRF+witness augmented attack recall: "
                f"**{pair['augmented']['event_recall']:.3f}**."
            ),
            "",
            "## Externally anchored authority provenance",
            "",
            (
                "Authority bundle SHA-256: "
                f"{summary['authority_bundle_sha256']}."
            ),
            (
                "Attested repository identity: "
                f"{summary['github_attestation_repository']}."
            ),
            (
                "Attested source digest: "
                f"{summary['github_attestation_source_digest']}."
            ),
            (
                "Required signer workflow: "
                f"{summary['github_attestation_signer_workflow']}."
            ),
            "",
            "## Interpretation boundary",
            "",
            (
                "Stage 31 closes the Stage-30 delivery-path key-substitution "
                "gap within the GitHub trust model: the complete authority "
                "bundle containing the ephemeral Ed25519 public key, signed "
                "epoch manifests and signatures is first verified against a "
                "GitHub Artifact Attestation bound to the repository, source "
                "digest and exact signer workflow, and only then extracted."
            ),
            (
                "A bit-modified copy of the authority bundle is explicitly "
                "submitted to the same GitHub attestation verifier and must "
                "fail before the detector pipeline can continue."
            ),
            (
                "This is stronger than accepting an unauthenticated ephemeral "
                "public key, but it is still not an independent hardware root "
                "of trust: GitHub OIDC, the GitHub attestation service, the "
                "workflow identity and GitHub control plane remain trusted."
            ),
            "",
            (
                "Instrumented native NRF source SHA-256: "
                f"{summary['instrumented_nrf_source_sha256']}."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage31_report")
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
            "Stage31 requires all eight preregistered runners"
        )

    rows = [
        evaluate_seed(
            labels[seed],
            alarms[seed],
            capture[seed],
            attest[seed],
        )
        for seed in EXPECTED_SEEDS
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
