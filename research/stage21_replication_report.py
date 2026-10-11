"""Stage 21 large-scale frozen replication audit.

This is an evaluation-only replication of the already frozen Stage-21
detector. It uses 128 new independent Open5GS runners, seeds 8501..8628.
No detector parameter is selected or modified here.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(8501, 8629))
METHOD_KEYS = {
    "page_hinkley": "page_hinkley_alert",
    "stage17_directional": "stage17_directional_alert",
    "stage19_sparse_directional": "stage19_sparse_directional_alert",
    "stage20_combined": "stage20_combined_alert",
    "stage21_combined": "stage21_combined_alert",
}
BOOTSTRAPS = 50000


def paired_ci(values, *, seed, n_boot=BOOTSTRAPS):
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
            raise AssertionError(
                f"Duplicate {filename} for seed {seed}"
            )
        output[seed] = doc
    return output


def evaluate_seed(labels: dict, alarms: dict, provenance: dict):
    seed = int(labels["seed"])
    if int(alarms["seed"]) != seed or int(provenance["seed"]) != seed:
        raise AssertionError("Stage21 replication artifact seed mismatch")
    if (
        not provenance["all_native_scp_upstream_http_200"]
        or provenance["min_native_nssf_profiles_seen_upstream"] < 2
        or provenance["native_open5gs_scp_binary_modified"]
        or provenance["stage18_fixed_sparse_schedule_reused"]
    ):
        raise AssertionError(
            "Stage21 replication provenance failed"
        )

    episodes = labels["episodes"]
    warmup = int(labels["warmup_ticks"])
    total = int(labels["total_ticks"])
    primary_episodes = [
        e for e in episodes if not e.get("boundary", False)
    ]
    boundary_episodes = [
        e for e in episodes if e.get("boundary", False)
    ]
    episode_ticks = {
        tick
        for episode in episodes
        for tick in range(
            int(episode["start_tick"]),
            int(episode["end_tick"]),
        )
    }
    clean_ticks = set(range(warmup, total)) - episode_ticks
    tick_rows = {
        int(row["tick"]): row for row in alarms["ticks"]
    }
    if set(tick_rows) != set(range(total)):
        raise AssertionError("Incomplete Stage21 replication alarm stream")

    methods = {}
    for method, key in METHOD_KEYS.items():
        alert_ticks = {
            tick
            for tick, row in tick_rows.items()
            if row[key]
        }
        false_alarms = len(alert_ticks & clean_ticks)

        def event_rows(selected):
            rows = []
            for episode in selected:
                start = int(episode["start_tick"])
                end = int(episode["end_tick"])
                inside = sorted(
                    tick
                    for tick in alert_ticks
                    if start <= tick < end
                )
                rows.append(
                    {
                        "kind": episode["kind"],
                        "detected": bool(inside),
                        "delay_ticks": (
                            inside[0] - start
                            if inside
                            else end - start
                        ),
                    }
                )
            return rows

        primary = event_rows(primary_episodes)
        boundary = event_rows(boundary_episodes)
        kinds = sorted({x["kind"] for x in primary})
        per_kind = {}
        for kind in kinds:
            rows = [x for x in primary if x["kind"] == kind]
            per_kind[kind] = {
                "event_recall": statistics.mean(
                    x["detected"] for x in rows
                ),
                "mean_horizon_penalized_delay_ticks": statistics.mean(
                    x["delay_ticks"] for x in rows
                ),
            }
        boundary_kinds = sorted({x["kind"] for x in boundary})
        boundary_recall = {
            kind: statistics.mean(
                x["detected"]
                for x in boundary
                if x["kind"] == kind
            )
            for kind in boundary_kinds
        }
        methods[method] = {
            "event_recall": statistics.mean(
                x["detected"] for x in primary
            ),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                x["delay_ticks"] for x in primary
            ),
            "false_alarms": false_alarms,
            "clean_ticks": len(clean_ticks),
            "false_alarms_per_1000_clean_ticks": (
                1000 * false_alarms / max(1, len(clean_ticks))
            ),
            "per_kind": per_kind,
            "boundary_recall": boundary_recall,
        }

    return {
        "seed": seed,
        "semantic_channel_enabled": alarms["calibration"][
            "semantic_channel_enabled"
        ],
        "semantic_selected_path_count": alarms["calibration"][
            "semantic_selected_path_count"
        ],
        "methods": methods,
    }


def summarize(rows):
    summary = {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "semantic_channel_enabled_fraction": statistics.mean(
            row["semantic_channel_enabled"] for row in rows
        ),
        "mean_semantic_selected_path_count": statistics.mean(
            row["semantic_selected_path_count"] for row in rows
        ),
        "methods": {},
    }
    kinds = sorted(
        rows[0]["methods"]["stage21_combined"]["per_kind"]
    )
    boundary_kinds = sorted(
        rows[0]["methods"]["stage21_combined"]["boundary_recall"]
    )
    for method in METHOD_KEYS:
        total_fa = sum(
            row["methods"][method]["false_alarms"]
            for row in rows
        )
        total_clean = sum(
            row["methods"][method]["clean_ticks"]
            for row in rows
        )
        summary["methods"][method] = {
            "event_recall": statistics.mean(
                row["methods"][method]["event_recall"]
                for row in rows
            ),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["methods"][method][
                    "mean_horizon_penalized_delay_ticks"
                ]
                for row in rows
            ),
            "false_alarms_total": total_fa,
            "clean_ticks_total": total_clean,
            "false_alarms_per_1000_clean_ticks": (
                1000 * total_fa / max(1, total_clean)
            ),
            "per_kind": {
                kind: {
                    "event_recall": statistics.mean(
                        row["methods"][method]["per_kind"][
                            kind
                        ]["event_recall"]
                        for row in rows
                    )
                }
                for kind in kinds
            },
            "boundary_recall": {
                kind: statistics.mean(
                    row["methods"][method]["boundary_recall"][
                        kind
                    ]
                    for row in rows
                )
                for kind in boundary_kinds
            },
        }

    def effect(challenger, comparator, seed_base):
        recall = [
            row["methods"][challenger]["event_recall"]
            - row["methods"][comparator]["event_recall"]
            for row in rows
        ]
        delay = [
            row["methods"][challenger][
                "mean_horizon_penalized_delay_ticks"
            ]
            - row["methods"][comparator][
                "mean_horizon_penalized_delay_ticks"
            ]
            for row in rows
        ]
        fa = [
            row["methods"][challenger][
                "false_alarms_per_1000_clean_ticks"
            ]
            - row["methods"][comparator][
                "false_alarms_per_1000_clean_ticks"
            ]
            for row in rows
        ]
        return {
            "event_recall_difference": statistics.mean(recall),
            "event_recall_difference_ci95": paired_ci(
                recall, seed=seed_base
            ),
            "delay_difference_ticks": statistics.mean(delay),
            "delay_difference_ci95_ticks": paired_ci(
                delay, seed=seed_base + 1
            ),
            "false_alarm_difference_per_1000": statistics.mean(fa),
            "false_alarm_difference_ci95_per_1000": paired_ci(
                fa, seed=seed_base + 2
            ),
        }

    summary["stage21_minus_stage20"] = effect(
        "stage21_combined", "stage20_combined", 21128
    )
    return summary


def markdown(summary):
    m = summary["methods"]
    effect = summary["stage21_minus_stage20"]
    labels = [
        ("page_hinkley", "Page-Hinkley"),
        ("stage17_directional", "Stage 17 directional"),
        ("stage19_sparse_directional", "Stage 19 sparse directional"),
        ("stage20_combined", "Stage 20 structural"),
        ("stage21_combined", "Stage 21 semantic + previous"),
    ]
    lines = [
        "# Stage 21 — 128-run frozen Open5GS replication",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"seeds {summary['seeds'][0]}..{summary['seeds'][-1]}."
        ),
        (
            "Detector configuration is identical to the frozen Stage-21 "
            "configuration used before the first live block 8401..8408."
        ),
        (
            "Semantic channel enabled fraction: "
            f"**{summary['semantic_channel_enabled_fraction']:.3f}**; "
            "mean selected stable paths: "
            f"**{summary['mean_semantic_selected_path_count']:.2f}**."
        ),
        "",
        "| Detector | Event recall | Penalized delay (ticks) | "
        "FA total | Clean ticks | FA / 1000 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for key, label in labels:
        row = m[key]
        lines.append(
            f"| {label} | {row['event_recall']:.3f} | "
            f"{row['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{row['false_alarms_total']} | "
            f"{row['clean_ticks_total']} | "
            f"{row['false_alarms_per_1000_clean_ticks']:.4f} |"
        )

    lines.extend(
        [
            "",
            "## Stage 21 minus Stage 20",
            "",
            (
                f"- Event recall: **{effect['event_recall_difference']:+.3f}**, "
                "95% runner-cluster bootstrap CI "
                f"[{effect['event_recall_difference_ci95'][0]:+.3f}, "
                f"{effect['event_recall_difference_ci95'][1]:+.3f}]."
            ),
            (
                f"- Penalized delay: **{effect['delay_difference_ticks']:+.2f} ticks**, "
                "95% CI "
                f"[{effect['delay_difference_ci95_ticks'][0]:+.2f}, "
                f"{effect['delay_difference_ci95_ticks'][1]:+.2f}]."
            ),
            (
                f"- False alarms / 1000: "
                f"**{effect['false_alarm_difference_per_1000']:+.4f}**, "
                "95% CI "
                f"[{effect['false_alarm_difference_ci95_per_1000'][0]:+.4f}, "
                f"{effect['false_alarm_difference_ci95_per_1000'][1]:+.4f}]."
            ),
            "",
            "## Per-family primary recall",
            "",
            "| Family | PH | Stage17 | Stage19 | Stage20 | Stage21 |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for kind in sorted(m["stage21_combined"]["per_kind"]):
        lines.append(
            f"| {kind} | "
            f"{m['page_hinkley']['per_kind'][kind]['event_recall']:.3f} | "
            f"{m['stage17_directional']['per_kind'][kind]['event_recall']:.3f} | "
            f"{m['stage19_sparse_directional']['per_kind'][kind]['event_recall']:.3f} | "
            f"{m['stage20_combined']['per_kind'][kind]['event_recall']:.3f} | "
            f"{m['stage21_combined']['per_kind'][kind]['event_recall']:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Predeclared relational boundary",
            "",
        ]
    )
    for kind, value in m["stage21_combined"]["boundary_recall"].items():
        lines.append(
            f"- {kind}: Stage21 recall **{value:.3f}**."
        )
    lines.extend(
        [
            "",
            "This replication is evaluation-only. Seeds 8501..8628 are now "
            "forbidden for any future detector tuning.",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument(
        "--output", default="stage21_replication_report"
    )
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
        missing = {
            "labels": sorted(expected - set(labels)),
            "alarms": sorted(expected - set(alarms)),
            "provenance": sorted(expected - set(provenance)),
        }
        raise AssertionError(
            f"Stage21 replication requires all 128 runners: {missing}"
        )

    rows = [
        evaluate_seed(
            labels[seed], alarms[seed], provenance[seed]
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
