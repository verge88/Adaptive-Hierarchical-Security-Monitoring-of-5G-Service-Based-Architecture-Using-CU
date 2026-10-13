"""Stage 22 post-hoc audit for the SCP-compromise boundary experiment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(8901, 8909))


def paired_ci(values, *, seed, n_boot=5000):
    rng = random.Random(seed)
    n = len(values)
    draws = sorted(
        statistics.mean(
            values[rng.randrange(n)] for _ in range(n)
        )
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
        raise AssertionError("Incomplete Stage22 alarm stream")

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

    per_kind = {}
    for kind in sorted({row["kind"] for row in event_rows}):
        selected = [row for row in event_rows if row["kind"] == kind]
        per_kind[kind] = statistics.mean(
            row["detected"] for row in selected
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
        "per_kind_recall": per_kind,
    }


def evaluate_seed(labels: dict, alarms: dict, provenance: dict) -> dict:
    seed = int(labels["seed"])
    if int(alarms["seed"]) != seed or int(provenance["seed"]) != seed:
        raise AssertionError("Stage22 artifact seed mismatch")
    required = (
        provenance["trusted_reference_bypasses_scp"]
        and provenance["trusted_reference_is_native_nrf"]
        and provenance["fault_injection_at_scp_output_boundary"]
        and provenance["all_native_scp_upstream_http_200"]
        and provenance["min_native_nssf_profiles_seen_upstream"] >= 2
        and not provenance["native_open5gs_scp_binary_modified"]
        and not provenance["native_open5gs_nrf_binary_modified"]
        and not provenance["native_binary_exploitation_performed"]
    )
    if not required:
        raise AssertionError("Stage22 provenance/trust-boundary audit failed")

    return {
        "seed": seed,
        "external_reference": score(
            labels, alarms["external_reference"]
        ),
        "common_path_control": score(
            labels, alarms["common_path_control"]
        ),
    }


def summarize(rows: list[dict]) -> dict:
    external_recall = [
        row["external_reference"]["event_recall"] for row in rows
    ]
    common_recall = [
        row["common_path_control"]["event_recall"] for row in rows
    ]
    gain = [
        ext - common
        for ext, common in zip(external_recall, common_recall)
    ]

    kinds = sorted(
        rows[0]["external_reference"]["per_kind_recall"]
    )
    return {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "external_reference": {
            "event_recall": statistics.mean(external_recall),
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
                gain, seed=220022
            ),
        },
    }


def markdown(summary: dict) -> str:
    ext = summary["external_reference"]
    common = summary["common_path_control"]
    gain = summary["independence_gain"]
    lines = [
        "# Stage 22 — SCP-compromise trust-boundary validation",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"seeds {summary['seeds'][0]}..{summary['seeds'][-1]}."
        ),
        "",
        "| Observation design | Event recall | Penalized delay | FA / 1000 |",
        "|---|---:|---:|---:|",
        (
            "| Direct native NRF reference outside SCP | "
            f"{ext['event_recall']:.3f} | "
            f"{ext['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{ext['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        (
            "| Common-path control below one compromised SCP | "
            f"{common['event_recall']:.3f} | "
            f"{common['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{common['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        "",
        (
            "Paired recall gain from moving the reference outside the SCP "
            f"trust domain: **{gain['event_recall_difference']:+.3f}**, "
            "95% runner-cluster bootstrap CI "
            f"[{gain['event_recall_difference_ci95'][0]:+.3f}, "
            f"{gain['event_recall_difference_ci95'][1]:+.3f}]."
        ),
        "",
        "## Per-family recall",
        "",
        "| Family | External NRF reference | Common-path control |",
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
            "## Interpretation boundary",
            "",
            (
                "Stage 22 is an effect-level component-compromise experiment. "
                "The genuine Open5GS SCP and NRF binaries remain unmodified; "
                "no exploit is used. The fault facade is allowed to corrupt "
                "the response at the SCP consumer-facing output boundary. "
                "Thus the experiment validates the independent-observer trust "
                "model for arbitrary SCP-output corruption, not exploitation "
                "of a particular Open5GS vulnerability."
            ),
            "",
            (
                "The common-path control intentionally gives both observations "
                "the same compromised view. It demonstrates the expected "
                "common-mode limitation: pairwise consistency cannot establish "
                "truth when both observations remain inside the attacker's "
                "control domain."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage22_report")
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
            "Stage22 requires all eight preregistered runners"
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
    (output / "REPORT.md").write_text(
        report, encoding="utf8"
    )
    print(report)


if __name__ == "__main__":
    main()
