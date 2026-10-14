"""Stage 23 post-hoc audit for native Open5GS SCP in-process mutation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(9001, 9009))


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
        raise AssertionError("Incomplete Stage23 alarm stream")

    alert_ticks = {
        tick
        for tick, row in rows.items()
        if row["stage21_combined_alert"]
    }
    event_rows = []
    for episode in episodes:
        start = int(episode["start_tick"])
        end = int(episode["end_tick"])
        inside = sorted(
            tick for tick in alert_ticks if start <= tick < end
        )
        event_rows.append(
            {
                "detected": bool(inside),
                "delay_ticks": (
                    inside[0] - start if inside else end - start
                ),
            }
        )

    return {
        "event_recall": statistics.mean(
            row["detected"] for row in event_rows
        ),
        "mean_horizon_penalized_delay_ticks": statistics.mean(
            row["delay_ticks"] for row in event_rows
        ),
        "false_alarms_per_1000_clean_ticks": (
            1000 * len(alert_ticks & clean_ticks)
            / max(1, len(clean_ticks))
        ),
        "semantic_channel_enabled": bool(
            detector["calibration"]["semantic_channel_enabled"]
        ),
        "semantic_selected_path_count": int(
            detector["calibration"]["semantic_selected_path_count"]
        ),
    }


def evaluate_seed(labels: dict, alarms: dict, provenance: dict) -> dict:
    seed = int(labels["seed"])
    if int(alarms["seed"]) != seed or int(provenance["seed"]) != seed:
        raise AssertionError("Stage23 artifact seed mismatch")

    expected_ticks = [
        int(tick)
        for episode in labels["episodes"]
        for tick in episode["mutation_ticks"]
    ]
    if labels["native_scp_log_mutation_ticks"] != expected_ticks:
        raise AssertionError("Stage23 native-SCP log schedule mismatch")
    if labels["native_scp_inprocess_log_marker_count"] != len(expected_ticks):
        raise AssertionError("Stage23 in-process marker count mismatch")

    required = (
        provenance["open5gs_source_ref"] == "v2.7.6"
        and provenance["consumer_request_sent_directly_to_open5gs_scpd"]
        and provenance["trusted_reference_bypasses_scp"]
        and not provenance["python_response_facade_on_consumer_path"]
        and provenance["native_scp_binary_contains_stage23_marker"]
        and provenance["native_scp_inprocess_marker_count"] == len(expected_ticks)
    )
    if not required:
        raise AssertionError("Stage23 provenance/trust-boundary audit failed")

    return {
        "seed": seed,
        "binary_sha256": provenance["native_scp_binary_sha256"],
        "source_sha256": provenance["instrumented_scp_source_sha256"],
        "external_reference": score(
            labels, alarms["external_reference"]
        ),
        "common_path_control": score(
            labels, alarms["common_path_control"]
        ),
    }


def summarize(rows: list[dict]) -> dict:
    binaries = {row["binary_sha256"] for row in rows}
    sources = {row["source_sha256"] for row in rows}
    if len(binaries) != 1 or len(sources) != 1:
        raise AssertionError(
            "Stage23 runners did not use identical native-SCP build/source"
        )

    ext_recall = [
        row["external_reference"]["event_recall"] for row in rows
    ]
    common_recall = [
        row["common_path_control"]["event_recall"] for row in rows
    ]
    gain = [
        ext - common
        for ext, common in zip(ext_recall, common_recall)
    ]

    return {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "native_scp_binary_sha256": next(iter(binaries)),
        "instrumented_source_sha256": next(iter(sources)),
        "episodes_per_runner": 6,
        "inprocess_mutations_per_runner": 18,
        "external_reference": {
            "event_recall": statistics.mean(ext_recall),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["external_reference"][
                    "mean_horizon_penalized_delay_ticks"
                ]
                for row in rows
            ),
            "false_alarms_per_1000_clean_ticks": statistics.mean(
                row["external_reference"][
                    "false_alarms_per_1000_clean_ticks"
                ]
                for row in rows
            ),
            "semantic_channel_enabled_fraction": statistics.mean(
                row["external_reference"]["semantic_channel_enabled"]
                for row in rows
            ),
        },
        "common_path_control": {
            "event_recall": statistics.mean(common_recall),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["common_path_control"][
                    "mean_horizon_penalized_delay_ticks"
                ]
                for row in rows
            ),
            "false_alarms_per_1000_clean_ticks": statistics.mean(
                row["common_path_control"][
                    "false_alarms_per_1000_clean_ticks"
                ]
                for row in rows
            ),
        },
        "independence_gain": {
            "event_recall_difference": statistics.mean(gain),
            "event_recall_difference_ci95": paired_ci(
                gain, seed=230023
            ),
        },
    }


def markdown(summary: dict) -> str:
    ext = summary["external_reference"]
    common = summary["common_path_control"]
    gain = summary["independence_gain"]
    lines = [
        "# Stage 23 — native Open5GS SCP in-process integrity experiment",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"seeds {summary['seeds'][0]}..{summary['seeds'][-1]}."
        ),
        (
            f"Episodes: **{summary['episodes_per_runner']} per runner**; "
            f"native in-process mutations: "
            f"**{summary['inprocess_mutations_per_runner']} per runner**."
        ),
        "",
        "| Observation design | Event recall | Penalized delay | FA / 1000 clean |",
        "|---|---:|---:|---:|",
        (
            "| Direct NRF reference outside native SCP | "
            f"{ext['event_recall']:.3f} | "
            f"{ext['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{ext['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        (
            "| Common-path control below same native SCP | "
            f"{common['event_recall']:.3f} | "
            f"{common['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{common['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        "",
        (
            "Paired recall gain from keeping the reference outside the "
            f"native SCP process: **{gain['event_recall_difference']:+.3f}**, "
            "95% runner-cluster bootstrap CI "
            f"[{gain['event_recall_difference_ci95'][0]:+.3f}, "
            f"{gain['event_recall_difference_ci95'][1]:+.3f}]."
        ),
        "",
        "## Native-process provenance",
        "",
        (
            "All runners used the same instrumented Open5GS v2.7.6 SCP "
            f"binary SHA-256: {summary['native_scp_binary_sha256']}."
        ),
        (
            "Instrumented src/scp/sbi-path.c SHA-256: "
            f"{summary['instrumented_source_sha256']}."
        ),
        "",
        (
            "The consumer connects directly to open5gs-scpd; there is no "
            "Python response facade on the consumer path. The response change "
            "is executed in src/scp/sbi-path.c::response_handler() before "
            "the stock ogs_sbi_server_send_response() call. The SCP log "
            "marker is joined with private labels only after blind detection."
        ),
        "",
        (
            "This is a controlled malicious-behaviour build of the native "
            "Open5GS SCP, not exploitation of an unknown or production CVE. "
            "It supports the claim that the frozen monitor detects false "
            "service data produced inside the SCP process when the reference "
            "observation is outside that SCP's control domain."
        ),
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage23_report")
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
        raise AssertionError(
            "Stage23 requires all eight preregistered runners"
        )

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
