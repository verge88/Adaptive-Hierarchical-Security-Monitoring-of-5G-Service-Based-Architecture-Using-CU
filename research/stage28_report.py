"""Stage 28 randomized robustness audit.

Unlike Stage 27, this report does not rely only on event recall. It also reports
mutation-tick alert coverage, attack-window alert occupancy, stratified recall,
and a Wilson interval over all randomized episodes.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(9501, 9509))
CHANNEL_KEYS = {
    "directional": "stage17_directional_alert",
    "sparse": "stage19_sparse_directional_alert",
    "structural": "stage20_structural_alert",
    "semantic": "stage21_semantic_alert",
    "combined": "stage21_combined_alert",
}


def wilson_interval(successes: int, total: int, z: float = 1.96) -> list[float]:
    if total <= 0:
        return [0.0, 0.0]
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    half = (
        z
        * math.sqrt(
            p * (1 - p) / total
            + z * z / (4 * total * total)
        )
        / denom
    )
    return [max(0.0, center - half), min(1.0, center + half)]


def paired_cluster_ci(values, *, seed, n_boot=5000):
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


def score(labels: dict, detector: dict) -> dict:
    warmup = int(labels["warmup_ticks"])
    total = int(labels["total_ticks"])
    episodes = labels["episodes"]
    rows = {int(row["tick"]): row for row in detector["ticks"]}
    if set(rows) != set(range(total)):
        raise AssertionError("Incomplete Stage28 alarm stream")

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

    output = {}
    for channel, key in CHANNEL_KEYS.items():
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
                    "duration_ticks": int(episode["duration_ticks"]),
                    "realized_density": float(episode["realized_density"]),
                    "multiplicity": int(episode["multiplicity"]),
                    "detected": bool(inside),
                    "delay_ticks": (
                        inside[0] - start if inside else end - start
                    ),
                }
            )

        detected = sum(int(row["detected"]) for row in event_rows)
        output[channel] = {
            "event_detected": detected,
            "event_total": len(event_rows),
            "event_recall": detected / len(event_rows),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["delay_ticks"] for row in event_rows
            ),
            "mutation_tick_alert_coverage": (
                len(alerts & mutation_ticks) / max(1, len(mutation_ticks))
            ),
            "attack_window_alert_fraction": (
                len(alerts & attack_window_ticks)
                / max(1, len(attack_window_ticks))
            ),
            "false_alarms_per_1000_clean_ticks": (
                1000 * len(alerts & clean_ticks)
                / max(1, len(clean_ticks))
            ),
            "episode_results": event_rows,
        }
    return output


def evaluate_seed(labels: dict, alarms: dict, capture: dict, attest: dict) -> dict:
    seed = int(labels["seed"])
    if any(
        int(doc["seed"]) != seed
        for doc in (alarms, capture, attest)
    ):
        raise AssertionError("Stage28 seed mismatch")
    if int(labels["stage"]) != 28 or int(capture["stage"]) != 28:
        raise AssertionError("Stage28 stage marker mismatch")
    if int(attest["stage"]) != 28:
        raise AssertionError("Stage28 attestation provenance mismatch")

    required = (
        capture["open5gs_source_ref"] == "v2.7.6"
        and capture["all_common_source_rows_equal"]
        and not capture["signed_attestation_available_to_capture_job"]
        and not capture["realized_private_plan_available_to_blind_detector"]
        and labels["distribution_preregistered_not_realized_schedule"]
        and attest["trust_mechanism_frozen_from_stage27"]
        and attest["attestation_signature_verified"]
        and attest["attestation_algorithm"] == "Ed25519"
        and not attest["authority_private_key_available_to_verifier"]
        and not attest["authority_private_key_uploaded"]
        and attest["pairwise_common_source_equal_in_raw_input"]
        and attest["manifest_expected_nssf_count"] == 2
        and attest["manifest_expected_registered_count"] == 2
    )
    if not required:
        raise AssertionError("Stage28 trust/protocol audit failed")

    return {
        "seed": seed,
        "native_nrf_binary_sha256": capture["native_nrf_binary_sha256"],
        "instrumented_nrf_source_sha256": capture[
            "instrumented_nrf_source_sha256"
        ],
        "private_plan_sha256": labels["private_plan_sha256"],
        "attested_reference": score(
            labels, alarms["external_reference"]
        ),
        "compromised_pair": score(
            labels, alarms["common_path_control"]
        ),
    }


def stratified_combined(rows: list[dict], field: str) -> dict:
    groups: dict[str, list[bool]] = {}
    for row in rows:
        for episode in row["attested_reference"]["combined"]["episode_results"]:
            key = str(episode[field])
            groups.setdefault(key, []).append(bool(episode["detected"]))
    return {
        key: {
            "detected": sum(values),
            "total": len(values),
            "recall": statistics.mean(values),
            "wilson95": wilson_interval(sum(values), len(values)),
        }
        for key, values in sorted(groups.items())
    }


def summarize(rows: list[dict]) -> dict:
    sources = {row["instrumented_nrf_source_sha256"] for row in rows}
    plans = {row["private_plan_sha256"] for row in rows}
    if len(sources) != 1:
        raise AssertionError("Stage28 runners used different NRF source")
    if len(plans) != len(rows):
        raise AssertionError("Stage28 runners did not realize independent plans")

    summary = {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "episodes_per_runner": 12,
        "total_randomized_episodes": 12 * len(rows),
        "unique_private_plan_count": len(plans),
        "instrumented_nrf_source_sha256": next(iter(sources)),
        "attested_reference": {},
        "compromised_pair": {},
    }

    for channel in CHANNEL_KEYS:
        att_success = sum(
            row["attested_reference"][channel]["event_detected"]
            for row in rows
        )
        att_total = sum(
            row["attested_reference"][channel]["event_total"]
            for row in rows
        )
        pair_success = sum(
            row["compromised_pair"][channel]["event_detected"]
            for row in rows
        )
        pair_total = sum(
            row["compromised_pair"][channel]["event_total"]
            for row in rows
        )

        summary["attested_reference"][channel] = {
            "event_detected": att_success,
            "event_total": att_total,
            "event_recall": att_success / att_total,
            "event_recall_wilson95": wilson_interval(
                att_success, att_total
            ),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["attested_reference"][channel][
                    "mean_horizon_penalized_delay_ticks"
                ]
                for row in rows
            ),
            "mutation_tick_alert_coverage": statistics.mean(
                row["attested_reference"][channel][
                    "mutation_tick_alert_coverage"
                ]
                for row in rows
            ),
            "attack_window_alert_fraction": statistics.mean(
                row["attested_reference"][channel][
                    "attack_window_alert_fraction"
                ]
                for row in rows
            ),
            "false_alarms_per_1000_clean_ticks": statistics.mean(
                row["attested_reference"][channel][
                    "false_alarms_per_1000_clean_ticks"
                ]
                for row in rows
            ),
        }
        summary["compromised_pair"][channel] = {
            "event_detected": pair_success,
            "event_total": pair_total,
            "event_recall": pair_success / pair_total,
            "event_recall_wilson95": wilson_interval(
                pair_success, pair_total
            ),
            "false_alarms_per_1000_clean_ticks": statistics.mean(
                row["compromised_pair"][channel][
                    "false_alarms_per_1000_clean_ticks"
                ]
                for row in rows
            ),
        }

    gains = [
        row["attested_reference"]["combined"]["event_recall"]
        - row["compromised_pair"]["combined"]["event_recall"]
        for row in rows
    ]
    summary["combined_attestation_gain"] = {
        "runner_mean_difference": statistics.mean(gains),
        "runner_cluster_bootstrap_ci95": paired_cluster_ci(
            gains, seed=280028
        ),
    }
    summary["combined_by_kind"] = stratified_combined(rows, "kind")
    summary["combined_by_duration_bin"] = stratified_combined(
        rows, "duration_bin"
    )
    summary["combined_by_density_bin"] = stratified_combined(
        rows, "density_bin"
    )
    return summary


def markdown(summary: dict) -> str:
    att = summary["attested_reference"]
    pair = summary["compromised_pair"]
    gain = summary["combined_attestation_gain"]
    lines = [
        "# Stage 28 — randomized common-source robustness stress",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"randomized episodes: **{summary['total_randomized_episodes']}**; "
            f"unique private plans: **{summary['unique_private_plan_count']}**."
        ),
        "",
        "| Frozen channel | Attested event recall | Wilson 95% | Colluding-pair recall | Mutation-tick coverage | Attack-window alarm fraction | FA / 1000 clean |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for channel in (
        "directional", "sparse", "structural", "semantic", "combined"
    ):
        ci = att[channel]["event_recall_wilson95"]
        lines.append(
            f"| {channel} | "
            f"{att[channel]['event_recall']:.3f} "
            f"({att[channel]['event_detected']}/{att[channel]['event_total']}) | "
            f"[{ci[0]:.3f}, {ci[1]:.3f}] | "
            f"{pair[channel]['event_recall']:.3f} | "
            f"{att[channel]['mutation_tick_alert_coverage']:.3f} | "
            f"{att[channel]['attack_window_alert_fraction']:.3f} | "
            f"{att[channel]['false_alarms_per_1000_clean_ticks']:.3f} |"
        )

    lines.extend(
        [
            "",
            (
                "Runner-cluster combined recall gain from the frozen signed "
                f"attestation domain: **{gain['runner_mean_difference']:+.3f}**, "
                "95% bootstrap CI "
                f"[{gain['runner_cluster_bootstrap_ci95'][0]:+.3f}, "
                f"{gain['runner_cluster_bootstrap_ci95'][1]:+.3f}]."
            ),
            "",
            "## Combined recall by attack family",
            "",
            "| Family | Detected / total | Recall | Wilson 95% |",
            "|---|---:|---:|---:|",
        ]
    )
    for name, row in summary["combined_by_kind"].items():
        ci = row["wilson95"]
        lines.append(
            f"| {name} | {row['detected']}/{row['total']} | "
            f"{row['recall']:.3f} | [{ci[0]:.3f}, {ci[1]:.3f}] |"
        )

    lines.extend(
        [
            "",
            "## Combined recall by duration",
            "",
            "| Duration bin | Detected / total | Recall | Wilson 95% |",
            "|---|---:|---:|---:|",
        ]
    )
    for name, row in summary["combined_by_duration_bin"].items():
        ci = row["wilson95"]
        lines.append(
            f"| {name} | {row['detected']}/{row['total']} | "
            f"{row['recall']:.3f} | [{ci[0]:.3f}, {ci[1]:.3f}] |"
        )

    lines.extend(
        [
            "",
            "## Combined recall by attack density",
            "",
            "| Density bin | Detected / total | Recall | Wilson 95% |",
            "|---|---:|---:|---:|",
        ]
    )
    for name, row in summary["combined_by_density_bin"].items():
        ci = row["wilson95"]
        lines.append(
            f"| {name} | {row['detected']}/{row['total']} | "
            f"{row['recall']:.3f} | [{ci[0]:.3f}, {ci[1]:.3f}] |"
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            (
                "Stage 28 deliberately removes the deterministic 12-of-12 "
                "attack pattern that made Stage 27 easy to separate. Episode "
                "duration, attack density, family, phantom multiplicity and "
                "clean gaps are randomized independently per runner. The "
                "realized schedules remain private until post-hoc audit."
            ),
            (
                "Event recall is therefore reported together with Wilson "
                "intervals and tick-level alert coverage. A value of 1.000, if "
                "observed, means every randomized episode in this finite block "
                "was detected; it does not imply universal 100% detection."
            ),
            (
                "The signed authority mechanism itself is frozen from Stage 27. "
                "Stage 28 tests robustness to a harder attack distribution, not "
                "a newly tuned detector or a stronger attestation oracle."
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
    parser.add_argument("--output", default="stage28_report")
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
            "Stage28 requires all eight preregistered runners"
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
