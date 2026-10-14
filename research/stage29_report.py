"""Stage 29 held-out audit for the attested-invariant channel.

Stage 28 is the design set. Stage 29 evaluates a frozen one-shot invariant rule
on fresh randomized schedules and reports both the original Stage-21 combined
alarm and the augmented Stage-29 alarm.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

from .stage28_report import wilson_interval

EXPECTED_SEEDS = tuple(range(9601, 9609))
ALARM_KEYS = {
    "legacy_combined": "stage21_combined_alert",
    "attested_invariant": "stage29_attested_invariant_alert",
    "augmented": "stage29_augmented_alert",
}


def cluster_bootstrap_ci(values, *, seed, n_boot=5000):
    rng = random.Random(seed)
    n = len(values)
    draws = sorted(
        statistics.mean(values[rng.randrange(n)] for _ in range(n))
        for _ in range(n_boot)
    )
    return [
        draws[int(0.025 * (n_boot - 1))],
        draws[int(0.975 * (n_boot - 1))],
    ]


def load_by_seed(root: Path, filename: str) -> dict[int, dict]:
    output = {}
    for path in root.rglob(filename):
        doc = json.loads(path.read_text(encoding="utf8"))
        seed = int(doc["seed"])
        if seed in output:
            raise AssertionError(f"Duplicate {filename} for seed {seed}")
        output[seed] = doc
    return output


def score_key(labels: dict, detector: dict, key: str) -> dict:
    warmup = int(labels["warmup_ticks"])
    total = int(labels["total_ticks"])
    episodes = labels["episodes"]
    rows = {int(row["tick"]): row for row in detector["ticks"]}
    if set(rows) != set(range(total)):
        raise AssertionError("Incomplete Stage29 detector stream")

    attack_window_ticks = {
        tick
        for episode in episodes
        for tick in range(
            int(episode["start_tick"]),
            int(episode["end_tick"]),
        )
    }
    mutation_ticks = {
        int(tick)
        for episode in episodes
        for tick in episode["mutation_ticks"]
    }
    clean_ticks = set(range(warmup, total)) - attack_window_ticks
    alerts = {
        tick
        for tick, row in rows.items()
        if bool(row.get(key, False))
    }

    episode_rows = []
    for episode in episodes:
        start = int(episode["start_tick"])
        end = int(episode["end_tick"])
        inside = sorted(t for t in alerts if start <= t < end)
        episode_rows.append(
            {
                "episode": int(episode["episode"]),
                "kind": episode["kind"],
                "duration_bin": episode["duration_bin"],
                "density_bin": episode["density_bin"],
                "duration_ticks": int(episode["duration_ticks"]),
                "realized_density": float(episode["realized_density"]),
                "multiplicity": int(episode["multiplicity"]),
                "detected": bool(inside),
                "delay_ticks": (
                    inside[0] - start if inside else end - start
                ),
            }
        )

    detected = sum(int(row["detected"]) for row in episode_rows)
    return {
        "event_detected": detected,
        "event_total": len(episode_rows),
        "event_recall": detected / len(episode_rows),
        "mean_horizon_penalized_delay_ticks": statistics.mean(
            row["delay_ticks"] for row in episode_rows
        ),
        "mutation_tick_alert_coverage": (
            len(alerts & mutation_ticks) / max(1, len(mutation_ticks))
        ),
        "attack_window_alert_fraction": (
            len(alerts & attack_window_ticks)
            / max(1, len(attack_window_ticks))
        ),
        "false_alarm_count": len(alerts & clean_ticks),
        "clean_tick_count": len(clean_ticks),
        "false_alarms_per_1000_clean_ticks": (
            1000 * len(alerts & clean_ticks) / max(1, len(clean_ticks))
        ),
        "episode_results": episode_rows,
    }


def evaluate_seed(labels: dict, alarms: dict, capture: dict, attest: dict) -> dict:
    seed = int(labels["seed"])
    if any(
        int(doc["seed"]) != seed
        for doc in (alarms, capture, attest)
    ):
        raise AssertionError("Stage29 seed mismatch")
    if int(labels["stage"]) != 29 or int(capture["stage"]) != 29:
        raise AssertionError("Stage29 capture marker mismatch")
    if int(attest["stage"]) != 29:
        raise AssertionError("Stage29 attestation marker mismatch")

    protocol = alarms.get("protocol", {})
    required = (
        labels["stage29_role"] == "held_out_validation"
        and labels["attack_distribution_frozen_from_stage28"]
        and capture["stage29_role"] == "held_out_validation"
        and capture["attack_generator_frozen_from_stage28"]
        and capture["detector_design_data_excluded_from_stage29_labels"]
        and not capture["signed_attestation_available_to_capture_job"]
        and not capture["realized_private_plan_available_to_blind_detector"]
        and attest["trust_mechanism_frozen_from_stage27"]
        and attest["projection_mechanism_frozen_from_stage28"]
        and attest["attestation_signature_verified"]
        and not attest["realized_attack_schedule_available_to_verifier"]
        and attest["pairwise_common_source_equal_in_raw_input"]
        and protocol.get("detector_retuned_for_stage29") is False
        and protocol.get("stage29_private_schedule_received") is False
        and protocol.get("stage29_rule_selected_from_stage28_design_set")
        and protocol.get("stage29_rule_has_numeric_threshold") is False
    )
    if not required:
        raise AssertionError("Stage29 preregistration/provenance audit failed")

    external = {
        name: score_key(
            labels,
            alarms["external_reference"],
            key,
        )
        for name, key in ALARM_KEYS.items()
    }
    pair = {
        name: score_key(
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
    }


def pooled(rows: list[dict], branch: str, channel: str) -> dict:
    successes = sum(
        row[branch][channel]["event_detected"] for row in rows
    )
    total = sum(
        row[branch][channel]["event_total"] for row in rows
    )
    false_alarms = sum(
        row[branch][channel]["false_alarm_count"] for row in rows
    )
    clean_ticks = sum(
        row[branch][channel]["clean_tick_count"] for row in rows
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
        "attack_window_alert_fraction": statistics.mean(
            row[branch][channel]["attack_window_alert_fraction"]
            for row in rows
        ),
        "false_alarm_count": false_alarms,
        "clean_tick_count": clean_ticks,
        "false_alarms_per_1000_clean_ticks": (
            1000 * false_alarms / max(1, clean_ticks)
        ),
    }


def stratified(rows: list[dict], channel: str, field: str) -> dict:
    groups: dict[str, dict[str, list[bool]]] = {}
    for row in rows:
        for branch_name in ("legacy_combined", "augmented"):
            for episode in row["external_reference"][branch_name][
                "episode_results"
            ]:
                key = str(episode[field])
                groups.setdefault(
                    key,
                    {"legacy_combined": [], "augmented": []},
                )[branch_name].append(bool(episode["detected"]))

    output = {}
    for key, values in sorted(groups.items()):
        legacy = values["legacy_combined"]
        augmented = values["augmented"]
        output[key] = {
            "total": len(legacy),
            "legacy_detected": sum(legacy),
            "legacy_recall": statistics.mean(legacy),
            "augmented_detected": sum(augmented),
            "augmented_recall": statistics.mean(augmented),
            "augmented_wilson95": wilson_interval(
                sum(augmented), len(augmented)
            ),
        }
    return output


def summarize(rows: list[dict]) -> dict:
    plans = {row["private_plan_sha256"] for row in rows}
    sources = {row["instrumented_nrf_source_sha256"] for row in rows}
    if len(plans) != len(rows):
        raise AssertionError("Stage29 private plans are not independent")
    if len(sources) != 1:
        raise AssertionError("Stage29 runners used different NRF source")

    summary = {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "total_randomized_episodes": 12 * len(rows),
        "unique_private_plan_count": len(plans),
        "instrumented_nrf_source_sha256": next(iter(sources)),
        "external_reference": {
            name: pooled(rows, "external_reference", name)
            for name in ALARM_KEYS
        },
        "compromised_pair": {
            name: pooled(rows, "compromised_pair", name)
            for name in ALARM_KEYS
        },
    }

    gains = [
        row["external_reference"]["augmented"]["event_recall"]
        - row["external_reference"]["legacy_combined"]["event_recall"]
        for row in rows
    ]
    pair_gains = [
        row["external_reference"]["augmented"]["event_recall"]
        - row["compromised_pair"]["augmented"]["event_recall"]
        for row in rows
    ]
    summary["heldout_gain_over_legacy"] = {
        "runner_mean_difference": statistics.mean(gains),
        "runner_cluster_bootstrap_ci95": cluster_bootstrap_ci(
            gains, seed=290029
        ),
    }
    summary["attestation_gain_over_colluding_pair"] = {
        "runner_mean_difference": statistics.mean(pair_gains),
        "runner_cluster_bootstrap_ci95": cluster_bootstrap_ci(
            pair_gains, seed=291029
        ),
    }
    summary["by_kind"] = stratified(rows, "augmented", "kind")
    summary["by_duration_bin"] = stratified(
        rows, "augmented", "duration_bin"
    )
    summary["by_density_bin"] = stratified(
        rows, "augmented", "density_bin"
    )
    return summary


def markdown(summary: dict) -> str:
    ext = summary["external_reference"]
    pair = summary["compromised_pair"]
    gain = summary["heldout_gain_over_legacy"]
    trust_gain = summary["attestation_gain_over_colluding_pair"]

    lines = [
        "# Stage 29 — held-out validation of the attested-invariant channel",
        "",
        (
            f"Fresh independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"held-out randomized episodes: "
            f"**{summary['total_randomized_episodes']}**; "
            f"unique private plans: "
            f"**{summary['unique_private_plan_count']}**."
        ),
        "",
        "| Detector view | Recall | Wilson 95% | Delay | Mutation-tick coverage | FA / 1000 clean |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, label in (
        ("legacy_combined", "Frozen Stage-21 combined"),
        ("attested_invariant", "Stage-29 invariant only"),
        ("augmented", "Augmented OR"),
    ):
        row = ext[name]
        ci = row["event_recall_wilson95"]
        lines.append(
            f"| {label} | {row['event_recall']:.3f} "
            f"({row['event_detected']}/{row['event_total']}) | "
            f"[{ci[0]:.3f}, {ci[1]:.3f}] | "
            f"{row['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{row['mutation_tick_alert_coverage']:.3f} | "
            f"{row['false_alarms_per_1000_clean_ticks']:.3f} |"
        )

    pair_row = pair["augmented"]
    lines.extend(
        [
            "",
            (
                "Held-out runner-cluster recall gain of augmented over legacy: "
                f"**{gain['runner_mean_difference']:+.3f}**, "
                "95% bootstrap CI "
                f"[{gain['runner_cluster_bootstrap_ci95'][0]:+.3f}, "
                f"{gain['runner_cluster_bootstrap_ci95'][1]:+.3f}]."
            ),
            (
                "Augmented recall gain over the colluding NRF+witness control: "
                f"**{trust_gain['runner_mean_difference']:+.3f}**, "
                "95% bootstrap CI "
                f"[{trust_gain['runner_cluster_bootstrap_ci95'][0]:+.3f}, "
                f"{trust_gain['runner_cluster_bootstrap_ci95'][1]:+.3f}]."
            ),
            (
                "Colluding-pair augmented recall: "
                f"**{pair_row['event_recall']:.3f}**; "
                "FA / 1000 clean: "
                f"**{pair_row['false_alarms_per_1000_clean_ticks']:.3f}**."
            ),
            "",
            "## Held-out stratification",
            "",
            "| Stratum | Legacy | Augmented | Augmented Wilson 95% |",
            "|---|---:|---:|---:|",
        ]
    )

    def add_group(title: str, group: dict):
        lines.append(f"| **{title}** |  |  |  |")
        for name, row in group.items():
            ci = row["augmented_wilson95"]
            lines.append(
                f"| {name} | "
                f"{row['legacy_recall']:.3f} "
                f"({row['legacy_detected']}/{row['total']}) | "
                f"{row['augmented_recall']:.3f} "
                f"({row['augmented_detected']}/{row['total']}) | "
                f"[{ci[0]:.3f}, {ci[1]:.3f}] |"
            )

    add_group("attack family", summary["by_kind"])
    add_group("duration", summary["by_duration_bin"])
    add_group("density", summary["by_density_bin"])

    legacy_fa = ext["legacy_combined"]["false_alarms_per_1000_clean_ticks"]
    aug_fa = ext["augmented"]["false_alarms_per_1000_clean_ticks"]
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            (
                "Stage 28 was used only as an exploratory design set. Its 15 "
                "combined false negatives motivated a discrete one-sample "
                "attested-invariant channel; no Stage-29 labels were used to "
                "choose or tune the rule."
            ),
            (
                "The new channel has no numeric threshold: after successful "
                "signature verification it alarms when the consumer NSSF count "
                "or semantic discrete projection differs from the signed "
                "reference. The original Stage-21 detector is retained and "
                "reported separately."
            ),
            (
                "Observed held-out false-alarm change: "
                f"{aug_fa - legacy_fa:+.3f} per 1000 clean samples "
                f"(legacy {legacy_fa:.3f}, augmented {aug_fa:.3f})."
            ),
            (
                "The rule is valid only for facts covered by a fresh trusted "
                "attestation baseline. It must not be generalized to arbitrary "
                "dynamic NF state without a baseline-update/freshness protocol."
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
    parser.add_argument("--output", default="stage29_report")
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
            "Stage29 requires all eight preregistered held-out runners"
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
