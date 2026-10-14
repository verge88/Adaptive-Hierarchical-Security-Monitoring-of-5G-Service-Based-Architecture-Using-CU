"""Stage 30 post-hoc audit for signed baseline freshness."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

from .stage28_report import wilson_interval

EXPECTED_SEEDS = tuple(range(9701, 9709))
ALARM_KEYS = {
    "legacy_combined": "stage21_combined_alert",
    "attested_invariant": "stage29_attested_invariant_alert",
    "augmented": "stage29_augmented_alert",
}
TRANSITION_TICKS = tuple(range(30, 50))


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


def score_alarm(labels: dict, detector: dict, key: str) -> dict:
    warmup = int(labels["warmup_ticks"])
    total = int(labels["total_ticks"])
    episodes = labels["episodes"]
    rows = {int(row["tick"]): row for row in detector["ticks"]}
    if set(rows) != set(range(total)):
        raise AssertionError("Incomplete Stage30 detector stream")

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

    event_rows = []
    for episode in episodes:
        start = int(episode["start_tick"])
        end = int(episode["end_tick"])
        inside = sorted(t for t in alerts if start <= t < end)
        event_rows.append(
            {
                "episode": int(episode["episode"]),
                "kind": episode["kind"],
                "duration_bin": episode["duration_bin"],
                "density_bin": episode["density_bin"],
                "detected": bool(inside),
                "delay_ticks": (
                    inside[0] - start if inside else end - start
                ),
            }
        )

    detected = sum(int(row["detected"]) for row in event_rows)
    transition_alerts = alerts & set(TRANSITION_TICKS)
    return {
        "event_detected": detected,
        "event_total": len(event_rows),
        "event_recall": detected / len(event_rows),
        "mean_horizon_penalized_delay_ticks": statistics.mean(
            row["delay_ticks"] for row in event_rows
        ),
        "mutation_tick_alert_coverage": (
            len(alerts & mutation_ticks) / max(1, len(mutation_ticks))
        ),
        "false_alarm_count": len(alerts & clean_ticks),
        "clean_tick_count": len(clean_ticks),
        "false_alarms_per_1000_clean_ticks": (
            1000 * len(alerts & clean_ticks) / max(1, len(clean_ticks))
        ),
        "legitimate_transition_alert_count": len(transition_alerts),
        "legitimate_transition_tick_count": len(TRANSITION_TICKS),
        "legitimate_transition_fa_per_1000": (
            1000 * len(transition_alerts) / len(TRANSITION_TICKS)
        ),
        "episode_results": event_rows,
    }


def evaluate_seed(
    labels: dict,
    alarms: dict,
    capture: dict,
    attest: dict,
) -> dict:
    seed = int(labels["seed"])
    if any(
        int(doc["seed"]) != seed
        for doc in (alarms, capture, attest)
    ):
        raise AssertionError("Stage30 seed mismatch")
    if int(labels["stage"]) != 30 or int(capture["stage"]) != 30:
        raise AssertionError("Stage30 capture stage mismatch")
    if int(attest["stage"]) != 30:
        raise AssertionError("Stage30 attestation stage mismatch")

    protocol = alarms.get("protocol", {})
    events = capture["legitimate_transition_events"]
    required = (
        capture["stage30_role"] == "held_out_freshness_validation"
        and capture["attack_generator_frozen_from_stage28"]
        and capture["detector_rule_frozen_from_stage29"]
        and not capture["signed_baseline_available_to_capture_job"]
        and not capture["realized_private_plan_available_to_blind_detector"]
        and capture["all_common_source_rows_equal"]
        and capture["legitimate_transition_ticks"] == [30, 40, 45]
        and len(events) == 3
        and events[0]["observed_after"] == [1, 1]
        and events[1]["observed_after"] == [2, 2]
        and events[2]["observed_after"] == [2, 2]
        and attest["signed_epoch_chain_verified"]
        and attest["epoch_sequence"] == [0, 1, 2, 3]
        and attest["monotonic_logical_freshness_enforced"]
        and not attest["trusted_wall_clock_used"]
        and attest["stale_replay_accepted"] == 0
        and attest["stale_replay_attempts"] > 0
        and attest["pairwise_common_source_equal_in_raw_input"]
        and not attest["realized_attack_schedule_available_to_verifier"]
        and protocol.get("detector_retuned_for_stage30") is False
        and protocol.get("stage29_rule_frozen_for_stage30")
        and protocol.get("stage30_private_attack_schedule_received") is False
    )
    if not required:
        raise AssertionError("Stage30 provenance/freshness audit failed")

    return {
        "seed": seed,
        "private_plan_sha256": labels["private_plan_sha256"],
        "instrumented_nrf_source_sha256": capture[
            "instrumented_nrf_source_sha256"
        ],
        "stale_replay_attempts": int(attest["stale_replay_attempts"]),
        "stale_replay_accepted": int(attest["stale_replay_accepted"]),
        "external_reference": {
            name: score_alarm(
                labels, alarms["external_reference"], key
            )
            for name, key in ALARM_KEYS.items()
        },
        "compromised_pair": {
            name: score_alarm(
                labels, alarms["common_path_control"], key
            )
            for name, key in ALARM_KEYS.items()
        },
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
        "false_alarm_count": false_alarms,
        "clean_tick_count": clean_ticks,
        "false_alarms_per_1000_clean_ticks": (
            1000 * false_alarms / max(1, clean_ticks)
        ),
        "legitimate_transition_alert_count": transition_alerts,
        "legitimate_transition_tick_count": transition_ticks,
        "legitimate_transition_fa_per_1000": (
            1000 * transition_alerts / max(1, transition_ticks)
        ),
        "legitimate_transition_zero_fa_wilson95": wilson_interval(
            transition_alerts, transition_ticks
        ),
    }


def stratified(rows: list[dict], field: str) -> dict:
    groups: dict[str, dict[str, list[bool]]] = {}
    for row in rows:
        for channel in ("legacy_combined", "augmented"):
            for episode in row["external_reference"][channel][
                "episode_results"
            ]:
                key = str(episode[field])
                groups.setdefault(
                    key, {"legacy_combined": [], "augmented": []}
                )[channel].append(bool(episode["detected"]))

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
        raise AssertionError("Stage30 private plans are not independent")
    if len(sources) != 1:
        raise AssertionError("Stage30 runners used different NRF source")

    replay_attempts = sum(row["stale_replay_attempts"] for row in rows)
    replay_accepted = sum(row["stale_replay_accepted"] for row in rows)

    summary = {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "total_randomized_attack_episodes": 12 * len(rows),
        "unique_private_plan_count": len(plans),
        "instrumented_nrf_source_sha256": next(iter(sources)),
        "signed_epoch_count": 4,
        "legitimate_transitions_per_runner": 3,
        "stale_replay_attempts": replay_attempts,
        "stale_replay_accepted": replay_accepted,
        "stale_replay_acceptance_rate": (
            replay_accepted / max(1, replay_attempts)
        ),
        "stale_replay_acceptance_wilson95": wilson_interval(
            replay_accepted, replay_attempts
        ),
        "external_reference": {
            name: pooled(rows, "external_reference", name)
            for name in ALARM_KEYS
        },
        "compromised_pair": {
            name: pooled(rows, "compromised_pair", name)
            for name in ALARM_KEYS
        },
        "by_kind": stratified(rows, "kind"),
        "by_duration_bin": stratified(rows, "duration_bin"),
        "by_density_bin": stratified(rows, "density_bin"),
    }

    gains = [
        row["external_reference"]["augmented"]["event_recall"]
        - row["external_reference"]["legacy_combined"]["event_recall"]
        for row in rows
    ]
    summary["heldout_gain_over_legacy"] = {
        "runner_mean_difference": statistics.mean(gains),
        "runner_cluster_bootstrap_ci95": cluster_bootstrap_ci(
            gains, seed=300030
        ),
    }
    return summary


def markdown(summary: dict) -> str:
    ext = summary["external_reference"]
    pair = summary["compromised_pair"]
    gain = summary["heldout_gain_over_legacy"]
    aug = ext["augmented"]
    transition_ci = aug["legitimate_transition_zero_fa_wilson95"]
    replay_ci = summary["stale_replay_acceptance_wilson95"]

    lines = [
        "# Stage 30 — signed baseline freshness with legitimate NF transitions",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"attack episodes: **{summary['total_randomized_attack_episodes']}**; "
            f"unique private plans: **{summary['unique_private_plan_count']}**."
        ),
        (
            f"Signed baseline epochs: **{summary['signed_epoch_count']}**; "
            f"legitimate live transitions: "
            f"**{summary['legitimate_transitions_per_runner']} per runner**."
        ),
        "",
        "| Detector | Attack recall | Wilson 95% | Delay | Mutation-tick coverage | FA / 1000 clean | Transition FA / 1000 |",
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
                "Legitimate-transition alerts for augmented detector: "
                f"**{aug['legitimate_transition_alert_count']}/"
                f"{aug['legitimate_transition_tick_count']}**, "
                "Wilson 95% event-probability interval "
                f"[{transition_ci[0]:.3f}, {transition_ci[1]:.3f}]."
            ),
            (
                "Stale/replay signed-baseline acceptance: "
                f"**{summary['stale_replay_accepted']}/"
                f"{summary['stale_replay_attempts']} = "
                f"{summary['stale_replay_acceptance_rate']:.3f}**, "
                f"Wilson 95% [{replay_ci[0]:.3f}, {replay_ci[1]:.3f}]."
            ),
            (
                "Colluding NRF+witness augmented attack recall: "
                f"**{pair['augmented']['event_recall']:.3f}**."
            ),
            "",
            "## Attack-family stratification",
            "",
            "| Family | Legacy | Augmented | Augmented Wilson 95% |",
            "|---|---:|---:|---:|",
        ]
    )
    for name, row in summary["by_kind"].items():
        ci = row["augmented_wilson95"]
        lines.append(
            f"| {name} | {row['legacy_recall']:.3f} "
            f"({row['legacy_detected']}/{row['total']}) | "
            f"{row['augmented_recall']:.3f} "
            f"({row['augmented_detected']}/{row['total']}) | "
            f"[{ci[0]:.3f}, {ci[1]:.3f}] |"
        )

    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            (
                "Stage 30 validates a software-rooted logical epoch protocol. "
                "The signed chain binds monotonic epoch numbers, expected NSSF "
                "cardinality and observation-tick validity intervals. Previous "
                "epochs are rejected after their signed validity window."
            ),
            (
                "The experiment performs real Open5GS NSSF stop/start/restart "
                "operations and waits for the live NRF Discovery state to settle "
                "before observations resume under the next signed epoch."
            ),
            (
                "Freshness here is logical, not wall-clock or hardware rooted. "
                "The result does not prove resistance to compromise of the "
                "authority job, GitHub Actions control plane, trusted clock, "
                "TPM/TEE, or arbitrary unscheduled production state changes."
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
    parser.add_argument("--output", default="stage30_report")
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
            "Stage30 requires all eight preregistered runners"
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
