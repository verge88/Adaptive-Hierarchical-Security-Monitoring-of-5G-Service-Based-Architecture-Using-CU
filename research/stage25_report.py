"""Stage 25 post-hoc audit for the full NRF-independent multichannel projection."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(9201, 9209))
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
    rows = {int(row["tick"]): row for row in detector["ticks"]}
    if set(rows) != set(range(total)):
        raise AssertionError("Incomplete Stage25 alarm stream")

    episode_ticks = {
        tick
        for episode in episodes
        for tick in range(int(episode["start_tick"]), int(episode["end_tick"]))
    }
    clean_ticks = set(range(warmup, total)) - episode_ticks

    channel_results = {}
    for name, key in CHANNEL_KEYS.items():
        alert_ticks = {
            tick for tick, row in rows.items() if bool(row.get(key, False))
        }
        event_rows = []
        for episode in episodes:
            start = int(episode["start_tick"])
            end = int(episode["end_tick"])
            inside = sorted(t for t in alert_ticks if start <= t < end)
            event_rows.append(
                {
                    "kind": episode["kind"],
                    "detected": bool(inside),
                    "delay_ticks": inside[0] - start if inside else end - start,
                }
            )

        per_kind = {}
        for kind in sorted({row["kind"] for row in event_rows}):
            selected = [row for row in event_rows if row["kind"] == kind]
            per_kind[kind] = statistics.mean(
                row["detected"] for row in selected
            )

        channel_results[name] = {
            "event_recall": statistics.mean(
                row["detected"] for row in event_rows
            ),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["delay_ticks"] for row in event_rows
            ),
            "false_alarms_per_1000_clean_ticks": (
                1000 * len(alert_ticks & clean_ticks) / max(1, len(clean_ticks))
            ),
            "per_kind_recall": per_kind,
        }

    return channel_results


def evaluate_seed(labels: dict, alarms: dict, provenance: dict) -> dict:
    seed = int(labels["seed"])
    if int(alarms["seed"]) != seed or int(provenance["seed"]) != seed:
        raise AssertionError("Stage25 artifact seed mismatch")
    if int(labels["stage"]) != 25 or int(provenance["stage"]) != 25:
        raise AssertionError("Stage25 stage marker mismatch")

    required = (
        provenance["open5gs_source_ref"] == "v2.7.6"
        and not provenance["trusted_reference_reads_nrf_discovery"]
        and provenance["same_projection_applied_to_trusted_and_consumer"]
        and provenance["numeric_channel_has_external_nrf_independent_reference"]
        and provenance["sparse_channel_has_external_nrf_independent_reference"]
        and provenance["structural_channel_has_external_nrf_independent_reference"]
        and provenance["semantic_channel_has_external_nrf_independent_reference"]
        and provenance["warmup_exact_pair_fraction"] == 1.0
    )
    if not required:
        raise AssertionError("Stage25 provenance/witness audit failed")

    calibration = alarms["external_channel_calibration"]
    if not (
        calibration["sparse_quorum_enabled"]
        and calibration["structural_channel_enabled"]
        and calibration["semantic_channel_enabled"]
        and calibration["structural_exact_fraction"] >= 0.98
    ):
        raise AssertionError("Stage25 did not enable all gated frozen channels")

    return {
        "seed": seed,
        "binary_sha256": provenance["native_nrf_binary_sha256"],
        "source_sha256": provenance["instrumented_nrf_source_sha256"],
        "warmup_exact_pair_fraction": provenance["warmup_exact_pair_fraction"],
        "external_reference": score(labels, alarms["external_reference"]),
        "common_path_control": score(labels, alarms["common_path_control"]),
        "calibration": calibration,
    }


def summarize(rows: list[dict]) -> dict:
    binaries = {row["binary_sha256"] for row in rows}
    sources = {row["source_sha256"] for row in rows}
    if len(sources) != 1:
        raise AssertionError("Stage25 runners used different NRF source")

    summary = {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "native_nrf_binary_sha256_values": sorted(binaries),
        "native_nrf_binary_sha256_unique_count": len(binaries),
        "instrumented_source_sha256": next(iter(sources)),
        "warmup_exact_pair_fraction": statistics.mean(
            row["warmup_exact_pair_fraction"] for row in rows
        ),
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
            "per_kind_recall": {
                kind: statistics.mean(
                    row["external_reference"][channel]["per_kind_recall"][kind]
                    for row in rows
                )
                for kind in rows[0]["external_reference"][channel][
                    "per_kind_recall"
                ]
            },
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

    gains = [
        row["external_reference"]["combined"]["event_recall"]
        - row["common_path_control"]["combined"]["event_recall"]
        for row in rows
    ]
    summary["independence_gain"] = {
        "combined_event_recall_difference": statistics.mean(gains),
        "combined_event_recall_difference_ci95": paired_ci(
            gains, seed=250025
        ),
    }
    summary["channel_enablement"] = {
        "sparse_enabled_fraction": statistics.mean(
            row["calibration"]["sparse_quorum_enabled"] for row in rows
        ),
        "structural_enabled_fraction": statistics.mean(
            row["calibration"]["structural_channel_enabled"] for row in rows
        ),
        "semantic_enabled_fraction": statistics.mean(
            row["calibration"]["semantic_channel_enabled"] for row in rows
        ),
        "structural_exact_fraction": statistics.mean(
            row["calibration"]["structural_exact_fraction"] for row in rows
        ),
    }
    return summary


def markdown(summary: dict) -> str:
    ext = summary["external_reference"]
    common = summary["common_path_control"]
    gain = summary["independence_gain"]
    lines = [
        "# Stage 25 — full NRF-independent multichannel witness projection",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"seeds {summary['seeds'][0]}..{summary['seeds'][-1]}."
        ),
        (
            "Projected warm-up exact paired fraction: "
            f"**{summary['warmup_exact_pair_fraction']:.3f}**."
        ),
        "",
        "| Frozen channel | External NRF-independent witness recall | Common-mode recall | FA / 1000 clean |",
        "|---|---:|---:|---:|",
    ]
    for channel in ("directional", "sparse", "structural", "semantic", "combined"):
        lines.append(
            f"| {channel} | {ext[channel]['event_recall']:.3f} | "
            f"{common[channel]['event_recall']:.3f} | "
            f"{ext[channel]['false_alarms_per_1000_clean_ticks']:.3f} |"
        )

    lines.extend(
        [
            "",
            (
                "Combined paired recall gain from moving the projected witness "
                "outside the NRF trust domain: "
                f"**{gain['combined_event_recall_difference']:+.3f}**, "
                "95% runner-cluster bootstrap CI "
                f"[{gain['combined_event_recall_difference_ci95'][0]:+.3f}, "
                f"{gain['combined_event_recall_difference_ci95'][1]:+.3f}]."
            ),
            "",
            "## Per-family channel recall",
            "",
            "| Channel | profile_drop | status_substitution |",
            "|---|---:|---:|",
        ]
    )
    for channel in ("directional", "sparse", "structural", "semantic", "combined"):
        kinds = ext[channel]["per_kind_recall"]
        lines.append(
            f"| {channel} | {kinds.get('profile_drop', 0.0):.3f} | "
            f"{kinds.get('status_substitution', 0.0):.3f} |"
        )

    lines.extend(
        [
            "",
            "## Channel calibration",
            "",
            (
                "Sparse gate enabled fraction: "
                f"{summary['channel_enablement']['sparse_enabled_fraction']:.3f}; "
                "structural enabled fraction: "
                f"{summary['channel_enablement']['structural_enabled_fraction']:.3f}; "
                "semantic enabled fraction: "
                f"{summary['channel_enablement']['semantic_enabled_fraction']:.3f}; "
                "structural warm-up exact fraction: "
                f"{summary['channel_enablement']['structural_exact_fraction']:.3f}."
            ),
            "",
            "## Provenance and claim boundary",
            "",
            (
                "Instrumented Open5GS v2.7.6 NRF binary SHA-256 unique count: "
                f"{summary['native_nrf_binary_sha256_unique_count']}; values: "
                f"{summary['native_nrf_binary_sha256_values']}."
            ),
            (
                "Instrumented src/nrf/nnrf-handler.c SHA-256: "
                f"{summary['instrumented_source_sha256']}."
            ),
            (
                "Stage 25 does not duplicate the complete NRF schema. Instead, "
                "both the NF-side witness and the consumer Discovery response "
                "are mapped to the same projection containing only independently "
                "attestable NSSF nfInstanceId, nfType and nfStatus facts. "
                "Canonical-byte, structural and semantic features are then "
                "computed from that common projection. This closes the Stage-24 "
                "pseudo-independence gap for all frozen channels on the monitored "
                "projection, not for arbitrary NRF fields outside that projection."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage25_report")
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
        raise AssertionError("Stage25 requires all eight preregistered runners")

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
