"""Stage 24 post-hoc audit for native NRF compromise with NF-side witness."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(9101, 9109))


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
        raise AssertionError("Incomplete Stage24 alarm stream")

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
                "kind": episode["kind"],
                "detected": bool(inside),
                "delay_ticks": (
                    inside[0] - start if inside else end - start
                ),
            }
        )

    kinds = sorted({row["kind"] for row in event_rows})
    per_kind = {
        kind: statistics.mean(
            row["detected"]
            for row in event_rows
            if row["kind"] == kind
        )
        for kind in kinds
    }

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
        "per_kind_recall": per_kind,
        "semantic_channel_enabled": bool(
            detector["calibration"]["semantic_channel_enabled"]
        ),
        "semantic_selected_path_count": int(
            detector["calibration"]["semantic_selected_path_count"]
        ),
        "semantic_selected_paths": list(
            detector["calibration"]["semantic_selected_paths"]
        ),
    }


def evaluate_seed(labels: dict, alarms: dict, provenance: dict) -> dict:
    seed = int(labels["seed"])
    if int(alarms["seed"]) != seed or int(provenance["seed"]) != seed:
        raise AssertionError("Stage24 artifact seed mismatch")

    expected = [
        {"tick": int(tick), "kind": episode["kind"]}
        for episode in labels["episodes"]
        for tick in episode["mutation_ticks"]
    ]
    if labels["native_nrf_log_mutations"] != expected:
        raise AssertionError("Stage24 native-NRF log schedule mismatch")
    if labels["native_nrf_inprocess_log_marker_count"] != len(expected):
        raise AssertionError("Stage24 native-NRF marker count mismatch")

    required = (
        provenance["open5gs_source_ref"] == "v2.7.6"
        and provenance["consumer_request_uses_stock_open5gs_scp"]
        and not provenance["python_response_facade_on_consumer_path"]
        and not provenance["trusted_reference_reads_nrf_discovery"]
        and provenance["trusted_reference_uses_nf_local_registration_logs"]
        and provenance["trusted_reference_uses_direct_nf_liveness"]
        and provenance["semantic_channel_has_external_nrf_independent_witness"]
        and provenance["numeric_channel_neutralized"]
        and provenance["structural_channel_neutralized"]
        and provenance["native_nrf_binary_contains_stage24_marker"]
        and provenance["native_nrf_inprocess_marker_count"] == len(expected)
        and len(provenance["witness_registration_ids"]) == 2
    )
    if not required:
        raise AssertionError("Stage24 provenance/witness audit failed")

    external = score(labels, alarms["external_reference"])
    common = score(labels, alarms["common_path_control"])
    if not external["semantic_channel_enabled"]:
        raise AssertionError("Stage24 semantic witness channel did not enable")

    return {
        "seed": seed,
        "binary_sha256": provenance["native_nrf_binary_sha256"],
        "source_sha256": provenance["instrumented_nrf_source_sha256"],
        "external_reference": external,
        "common_path_control": common,
    }


def summarize(rows: list[dict]) -> dict:
    binaries = {row["binary_sha256"] for row in rows}
    sources = {row["source_sha256"] for row in rows}
    if len(sources) != 1:
        raise AssertionError(
            "Stage24 runners did not use identical instrumented NRF source"
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

    kinds = sorted(
        rows[0]["external_reference"]["per_kind_recall"]
    )
    selected_sets = {
        tuple(row["external_reference"]["semantic_selected_paths"])
        for row in rows
    }

    return {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "episodes_per_runner": 6,
        "inprocess_mutations_per_runner": 18,
        "native_nrf_binary_sha256_values": sorted(binaries),
        "native_nrf_binary_sha256_unique_count": len(binaries),
        "instrumented_source_sha256": next(iter(sources)),
        "semantic_selected_path_sets": [
            list(item) for item in sorted(selected_sets)
        ],
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
            "per_kind_recall": {
                kind: statistics.mean(
                    row["external_reference"]["per_kind_recall"][kind]
                    for row in rows
                )
                for kind in kinds
            },
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
            "per_kind_recall": {
                kind: statistics.mean(
                    row["common_path_control"]["per_kind_recall"][kind]
                    for row in rows
                )
                for kind in kinds
            },
        },
        "independence_gain": {
            "event_recall_difference": statistics.mean(gain),
            "event_recall_difference_ci95": paired_ci(
                gain, seed=240024
            ),
        },
    }


def markdown(summary: dict) -> str:
    ext = summary["external_reference"]
    common = summary["common_path_control"]
    gain = summary["independence_gain"]

    lines = [
        "# Stage 24 — native Open5GS NRF compromise with NF-side witness",
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
            "| NF-side witness outside NRF | "
            f"{ext['event_recall']:.3f} | "
            f"{ext['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{ext['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        (
            "| Common-mode control using compromised NRF view | "
            f"{common['event_recall']:.3f} | "
            f"{common['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{common['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        "",
        (
            "Paired recall gain from moving the semantic witness outside the "
            f"NRF trust domain: **{gain['event_recall_difference']:+.3f}**, "
            "95% runner-cluster bootstrap CI "
            f"[{gain['event_recall_difference_ci95'][0]:+.3f}, "
            f"{gain['event_recall_difference_ci95'][1]:+.3f}]."
        ),
        "",
        "## Per-family recall",
        "",
        "| Native NRF fault family | External NF-side witness | Common-mode |",
        "|---|---:|---:|",
    ]
    for kind in sorted(ext["per_kind_recall"]):
        lines.append(
            f"| {kind} | {ext['per_kind_recall'][kind]:.3f} | "
            f"{common['per_kind_recall'][kind]:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Provenance and claim boundary",
            "",
            (
                "Instrumented Open5GS v2.7.6 NRF binary SHA-256 unique "
                f"count: {summary['native_nrf_binary_sha256_unique_count']}; "
                f"values: {summary['native_nrf_binary_sha256_values']}."
            ),
            (
                "Instrumented src/nrf/nnrf-handler.c SHA-256: "
                f"{summary['instrumented_source_sha256']}."
            ),
            (
                "The consumer path is stock Open5GS SCP -> instrumented native "
                "NRF. The trusted semantic witness does not query NRF Discovery; "
                "it is reconstructed from the two NSSF processes' own local "
                "registered-state log records plus direct HTTP/2 liveness "
                "observations. Numeric and structural channels are neutralized, "
                "so Stage 24 validates the frozen semantic channel under an "
                "NRF-independent witness rather than claiming independent "
                "NRF truth for every channel."
            ),
            (
                "The native NRF mutation is executed inside "
                "nrf_nnrf_handle_nf_discover() before the stock response send. "
                "Internal registry state is left unchanged. This is a "
                "controlled malicious-behaviour build, not exploitation of a "
                "production CVE."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage24_report")
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
            "Stage24 requires all eight preregistered runners"
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
