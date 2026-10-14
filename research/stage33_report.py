"""Stage 33 final post-hoc audit.

Private labels are joined only after the external verifier has emitted a signed
verdict. The audit never recomputes detector alarms.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics

from .stage28_report import wilson_interval
from .stage30_report import load_by_seed, score_alarm

EXPECTED_SEEDS = tuple(range(10001, 10009))
ALARM_KEYS = {
    "legacy_combined": "stage21_combined_alert",
    "attested_invariant": "stage29_attested_invariant_alert",
    "augmented": "stage29_augmented_alert",
}


def evaluate_seed(labels, alarms, capture, verdict_provenance):
    seed = int(labels["seed"])
    if any(
        int(doc["seed"]) != seed
        for doc in (alarms, capture, verdict_provenance)
    ):
        raise AssertionError("Stage33 seed mismatch")

    required = (
        int(labels["stage"]) == 33
        and int(capture["stage"]) == 33
        and int(verdict_provenance["stage"]) == 33
        and labels["stage33_role"]
        == "held_out_external_verifier_validation"
        and capture["stage33_role"]
        == "held_out_external_verifier_validation"
        and capture["external_verifier_receives_private_labels"] is False
        and capture["stage29_detector_rule_frozen"]
        and capture["stage30_freshness_protocol_frozen"]
        and capture["stage28_attack_generator_frozen"]
        and verdict_provenance[
            "external_verdict_signature_verified"
        ]
        and verdict_provenance["external_execution"]
        and verdict_provenance[
            "private_labels_received_by_external_verifier"
        ]
        is False
        and verdict_provenance["policy_sha256"]
        and verdict_provenance["verifier_public_key_sha256"]
    )
    if not required:
        raise AssertionError("Stage33 provenance audit failed")

    external = {
        name: score_alarm(
            labels,
            alarms["external_reference"],
            key,
        )
        for name, key in ALARM_KEYS.items()
    }
    pair = {
        name: score_alarm(
            labels,
            alarms["common_path_control"],
            key,
        )
        for name, key in ALARM_KEYS.items()
    }

    return {
        "seed": seed,
        "private_plan_sha256": labels["private_plan_sha256"],
        "instrumented_nrf_source_sha256": capture[
            "instrumented_nrf_source_sha256"
        ],
        "external_reference": external,
        "compromised_pair": pair,
        "policy_sha256": verdict_provenance["policy_sha256"],
        "verifier_public_key_sha256": verdict_provenance[
            "verifier_public_key_sha256"
        ],
        "external_root_key_arn": verdict_provenance[
            "external_root_key_arn"
        ],
        "external_root_public_key_sha256": verdict_provenance[
            "external_root_public_key_sha256"
        ],
        "verdict_sha256": verdict_provenance["verdict_sha256"],
        "request_telemetry_sha256": verdict_provenance[
            "request_telemetry_sha256"
        ],
    }


def pooled(rows, branch, channel):
    successes = sum(
        row[branch][channel]["event_detected"] for row in rows
    )
    total = sum(
        row[branch][channel]["event_total"] for row in rows
    )
    fa = sum(
        row[branch][channel]["false_alarm_count"] for row in rows
    )
    clean = sum(
        row[branch][channel]["clean_tick_count"] for row in rows
    )
    transition_alerts = sum(
        row[branch][channel]["legitimate_transition_alert_count"]
        for row in rows
    )
    transition_ticks = sum(
        row[branch][channel]["legitimate_transition_tick_count"]
        for row in rows
    )
    return {
        "event_detected": successes,
        "event_total": total,
        "event_recall": successes / total,
        "event_recall_wilson95": wilson_interval(successes, total),
        "mean_horizon_penalized_delay_ticks": statistics.mean(
            row[branch][channel][
                "mean_horizon_penalized_delay_ticks"
            ]
            for row in rows
        ),
        "mutation_tick_alert_coverage": statistics.mean(
            row[branch][channel]["mutation_tick_alert_coverage"]
            for row in rows
        ),
        "false_alarm_count": fa,
        "clean_tick_count": clean,
        "false_alarms_per_1000_clean_ticks": (
            1000 * fa / max(1, clean)
        ),
        "legitimate_transition_alert_count": transition_alerts,
        "legitimate_transition_tick_count": transition_ticks,
        "legitimate_transition_fa_per_1000": (
            1000 * transition_alerts / max(1, transition_ticks)
        ),
        "legitimate_transition_wilson95": wilson_interval(
            transition_alerts,
            transition_ticks,
        ),
    }


def summarize(rows):
    plans = {row["private_plan_sha256"] for row in rows}
    policies = {row["policy_sha256"] for row in rows}
    verifier_keys = {
        row["verifier_public_key_sha256"] for row in rows
    }
    root_keys = {row["external_root_key_arn"] for row in rows}
    root_public = {
        row["external_root_public_key_sha256"] for row in rows
    }
    source_hashes = {
        row["instrumented_nrf_source_sha256"] for row in rows
    }

    if len(plans) != len(rows):
        raise AssertionError("Stage33 private plans are not independent")
    if any(
        len(group) != 1
        for group in (
            policies,
            verifier_keys,
            root_keys,
            root_public,
            source_hashes,
        )
    ):
        raise AssertionError(
            "Stage33 runners did not share one external trust configuration"
        )

    return {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "total_randomized_attack_episodes": 12 * len(rows),
        "unique_private_plan_count": len(plans),
        "externally_signed_verdict_count": len(rows),
        "policy_sha256": next(iter(policies)),
        "verifier_public_key_sha256": next(iter(verifier_keys)),
        "external_root_key_arn": next(iter(root_keys)),
        "external_root_public_key_sha256": next(iter(root_public)),
        "instrumented_nrf_source_sha256": next(iter(source_hashes)),
        "external_reference": {
            name: pooled(rows, "external_reference", name)
            for name in ALARM_KEYS
        },
        "compromised_pair": {
            name: pooled(rows, "compromised_pair", name)
            for name in ALARM_KEYS
        },
    }


def markdown(summary):
    ext = summary["external_reference"]
    pair = summary["compromised_pair"]
    lines = [
        "# Stage 33 — final external-verifier experiment",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"randomized attack episodes: "
            f"**{summary['total_randomized_attack_episodes']}**; "
            f"unique private plans: "
            f"**{summary['unique_private_plan_count']}**."
        ),
        (
            "Externally computed and signature-verified verdicts: "
            f"**{summary['externally_signed_verdict_count']}/"
            f"{summary['independent_live_runners']}**."
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

    aug = ext["augmented"]
    tci = aug["legitimate_transition_wilson95"]
    lines.extend(
        [
            "",
            (
                "Legitimate-transition alerts: "
                f"**{aug['legitimate_transition_alert_count']}/"
                f"{aug['legitimate_transition_tick_count']}**, "
                f"Wilson 95% [{tci[0]:.3f}, {tci[1]:.3f}]."
            ),
            (
                "Colluding NRF+witness augmented recall: "
                f"**{pair['augmented']['event_recall']:.3f}**."
            ),
            "",
            "## External trust material",
            "",
            f"Policy SHA-256: {summary['policy_sha256']}",
            (
                "External verifier public-key SHA-256: "
                f"{summary['verifier_public_key_sha256']}"
            ),
            f"External KMS key ARN: {summary['external_root_key_arn']}",
            (
                "External KMS public-key SHA-256: "
                f"{summary['external_root_public_key_sha256']}"
            ),
            "",
            "## Interpretation boundary",
            "",
            (
                "Stage 33 moves trusted projection and detector execution "
                "outside GitHub Actions. The external service receives only "
                "label-free telemetry and an externally KMS-approved policy, "
                "then emits a signed detector verdict."
            ),
            (
                "GitHub performs only post-hoc signature verification and "
                "statistical label joining. It does not recompute detector "
                "alarms in the final protocol."
            ),
            (
                "Capture still executes on GitHub-hosted runners, and the "
                "external verifier hosting provider is now part of the trusted "
                "computing base. The experiment therefore isolates the "
                "decision plane from GitHub; it does not make telemetry capture "
                "or every infrastructure dependency Byzantine-independent."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage33_report")
    args = parser.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    alarms = load_by_seed(root, "alarms.json")
    capture = load_by_seed(root, "provenance.json")
    verdicts = load_by_seed(root, "external_verdict_provenance.json")

    expected = set(EXPECTED_SEEDS)
    if any(
        set(group) != expected
        for group in (labels, alarms, capture, verdicts)
    ):
        raise AssertionError(
            "Stage33 requires all eight preregistered final runners"
        )

    rows = [
        evaluate_seed(
            labels[seed],
            alarms[seed],
            capture[seed],
            verdicts[seed],
        )
        for seed in EXPECTED_SEEDS
    ]
    summary = summarize(rows)

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "seed_results.json").write_text(
        json.dumps(rows, indent=2),
        encoding="utf8",
    )
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf8",
    )
    report = markdown(summary)
    (output / "REPORT.md").write_text(report, encoding="utf8")
    print(report)


if __name__ == "__main__":
    main()
