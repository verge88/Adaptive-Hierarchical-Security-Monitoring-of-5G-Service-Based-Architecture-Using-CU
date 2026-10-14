"""Stage 26 post-hoc audit for persistent phantom-profile NRF attack."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(9301, 9309))
CHANNEL_KEYS = {
    "directional": "stage17_directional_alert",
    "sparse": "stage19_sparse_directional_alert",
    "structural": "stage20_structural_alert",
    "semantic": "stage21_semantic_alert",
    "combined": "stage21_combined_alert",
}


def paired_ci(values, *, seed, n_boot=5000):
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
    episode_ticks = {
        tick
        for episode in episodes
        for tick in range(
            int(episode["start_tick"]),
            int(episode["end_tick"]),
        )
    }
    clean_ticks = set(range(warmup, total)) - episode_ticks
    rows = {int(row["tick"]): row for row in detector["ticks"]}
    if set(rows) != set(range(total)):
        raise AssertionError("Incomplete Stage26 detector stream")

    result = {}
    for channel, key in CHANNEL_KEYS.items():
        alerts = {
            tick for tick, row in rows.items() if bool(row.get(key, False))
        }
        event_rows = []
        for episode in episodes:
            start = int(episode["start_tick"])
            end = int(episode["end_tick"])
            inside = sorted(t for t in alerts if start <= t < end)
            event_rows.append(
                {
                    "detected": bool(inside),
                    "delay_ticks": inside[0] - start if inside else end - start,
                }
            )
        result[channel] = {
            "event_recall": statistics.mean(
                row["detected"] for row in event_rows
            ),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["delay_ticks"] for row in event_rows
            ),
            "false_alarms_per_1000_clean_ticks": (
                1000 * len(alerts & clean_ticks) / max(1, len(clean_ticks))
            ),
        }
    return result


def evaluate_seed(labels: dict, alarms: dict, provenance: dict) -> dict:
    seed = int(labels["seed"])
    if int(alarms["seed"]) != seed or int(provenance["seed"]) != seed:
        raise AssertionError("Stage26 artifact seed mismatch")
    if int(labels["stage"]) != 26 or int(provenance["stage"]) != 26:
        raise AssertionError("Stage26 stage marker mismatch")
    if labels["native_nrf_inprocess_log_marker_count"] != 72:
        raise AssertionError("Stage26 requires 72 native in-process mutations")

    required = (
        provenance["open5gs_source_ref"] == "v2.7.6"
        and not provenance["trusted_reference_reads_nrf_discovery"]
        and provenance["same_projection_applied_to_trusted_and_consumer"]
        and provenance["directional_numeric_reference_independent_of_nrf"]
        and provenance["attack_family"] == "phantom_profile_persistent"
        and provenance["persistent_attack_samples_per_episode"] == 12
        and provenance["warmup_exact_pair_fraction"] == 1.0
        and provenance["native_nrf_binary_contains_stage26_marker"]
    )
    if not required:
        raise AssertionError("Stage26 provenance audit failed")

    return {
        "seed": seed,
        "binary_sha256": provenance["native_nrf_binary_sha256"],
        "source_sha256": provenance["instrumented_nrf_source_sha256"],
        "external_reference": score(
            labels, alarms["external_reference"]
        ),
        "common_path_control": score(
            labels, alarms["common_path_control"]
        ),
        "calibration": alarms["external_channel_calibration"],
    }


def summarize(rows: list[dict]) -> dict:
    binaries = {row["binary_sha256"] for row in rows}
    sources = {row["source_sha256"] for row in rows}
    if len(sources) != 1:
        raise AssertionError("Stage26 runners used different NRF source")

    summary = {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "episodes_per_runner": 6,
        "mutations_per_runner": 72,
        "native_nrf_binary_sha256_values": sorted(binaries),
        "instrumented_source_sha256": next(iter(sources)),
        "external_reference": {},
        "common_path_control": {},
    }
    for channel in CHANNEL_KEYS:
        ext = [row["external_reference"][channel]["event_recall"] for row in rows]
        com = [row["common_path_control"][channel]["event_recall"] for row in rows]
        summary["external_reference"][channel] = {
            "event_recall": statistics.mean(ext),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["external_reference"][channel][
                    "mean_horizon_penalized_delay_ticks"
                ]
                for row in rows
            ),
            "false_alarms_per_1000_clean_ticks": statistics.mean(
                row["external_reference"][channel][
                    "false_alarms_per_1000_clean_ticks"
                ]
                for row in rows
            ),
        }
        summary["common_path_control"][channel] = {
            "event_recall": statistics.mean(com),
            "false_alarms_per_1000_clean_ticks": statistics.mean(
                row["common_path_control"][channel][
                    "false_alarms_per_1000_clean_ticks"
                ]
                for row in rows
            ),
        }

    gain = [
        row["external_reference"]["directional"]["event_recall"]
        - row["common_path_control"]["directional"]["event_recall"]
        for row in rows
    ]
    summary["directional_independence_gain"] = {
        "event_recall_difference": statistics.mean(gain),
        "event_recall_difference_ci95": paired_ci(
            gain, seed=260026
        ),
    }
    return summary


def markdown(summary: dict) -> str:
    ext = summary["external_reference"]
    com = summary["common_path_control"]
    gain = summary["directional_independence_gain"]
    lines = [
        "# Stage 26 — persistent phantom profile directional validation",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"seeds {summary['seeds'][0]}..{summary['seeds'][-1]}."
        ),
        (
            f"Episodes: **{summary['episodes_per_runner']} per runner**; "
            f"native in-process mutations: **{summary['mutations_per_runner']} "
            "per runner**."
        ),
        "",
        "| Frozen channel | External witness recall | Common-mode recall | Penalized delay | FA / 1000 clean |",
        "|---|---:|---:|---:|---:|",
    ]
    for channel in (
        "directional", "sparse", "structural", "semantic", "combined"
    ):
        lines.append(
            f"| {channel} | {ext[channel]['event_recall']:.3f} | "
            f"{com[channel]['event_recall']:.3f} | "
            f"{ext[channel]['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{ext[channel]['false_alarms_per_1000_clean_ticks']:.3f} |"
        )
    lines.extend(
        [
            "",
            (
                "Directional paired recall gain from an NRF-independent "
                f"reference: **{gain['event_recall_difference']:+.3f}**, "
                "95% runner-cluster bootstrap CI "
                f"[{gain['event_recall_difference_ci95'][0]:+.3f}, "
                f"{gain['event_recall_difference_ci95'][1]:+.3f}]."
            ),
            "",
            "## Provenance and interpretation",
            "",
            (
                "Instrumented Open5GS v2.7.6 NRF binary SHA-256 values: "
                f"{summary['native_nrf_binary_sha256_values']}."
            ),
            (
                "Instrumented src/nrf/nnrf-handler.c SHA-256: "
                f"{summary['instrumented_source_sha256']}."
            ),
            (
                "The persistent phantom NSSF profile is injected inside the "
                "native NRF Discovery response path for all 12 samples of each "
                "attack episode. The trusted reference remains the Stage-25 "
                "NF-side witness projection and never queries NRF Discovery. "
                "This experiment tests sensitivity of the already frozen "
                "directional mechanism to sustained NRF-generated distribution "
                "shift; it does not retune the detector or claim a production "
                "Open5GS exploit."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage26_report")
    args = parser.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    alarms = load_by_seed(root, "alarms.json")
    provenance = load_by_seed(root, "provenance.json")
    expected = set(EXPECTED_SEEDS)
    if (
        set(labels) != expected
        or set(alarms) != expected
        or set(provenance) != expected
    ):
        raise AssertionError("Stage26 requires all eight preregistered runners")

    rows = [
        evaluate_seed(labels[seed], alarms[seed], provenance[seed])
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
