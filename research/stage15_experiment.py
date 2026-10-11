"""Held-out Stage 15 comparison and paired confidence intervals."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import random
import statistics

from .stage15_detector import run_seed

DEFAULT_START_SEED = 2001
DEFAULT_SEEDS = 80
DETECTORS = (
    "legacy_static",
    "tuned_static",
    "hierarchical_e_cusum",
)


def paired_ci(differences, *, seed=15015, n_boot=5000):
    rng = random.Random(seed)
    n = len(differences)
    samples = sorted(
        statistics.mean(
            differences[rng.randrange(n)]
            for _ in range(n)
        )
        for _ in range(n_boot)
    )
    return [
        samples[int(0.025 * (n_boot - 1))],
        samples[int(0.975 * (n_boot - 1))],
    ]


def run(seeds):
    rows = []
    for seed in seeds:
        rows.extend(run_seed(seed))
    return rows


def summarize(rows):
    summary = {}
    for detector in DETECTORS:
        selected = [
            row for row in rows
            if row["detector"] == detector
        ]
        summary[detector] = {
            key: statistics.mean(row[key] for row in selected)
            for key in (
                "event_recall",
                "mean_censored_delay_s",
                "false_alarms_per_1000_clean_checks",
                "alarm_precision",
                "checked_sample_recall",
                "checked_sample_f1",
                "probes",
            )
        }

    static = {
        row["seed"]: row
        for row in rows
        if row["detector"] == "tuned_static"
    }
    evidence = {
        row["seed"]: row
        for row in rows
        if row["detector"] == "hierarchical_e_cusum"
    }
    common = sorted(set(static) & set(evidence))

    recall_diff = [
        evidence[seed]["event_recall"]
        - static[seed]["event_recall"]
        for seed in common
    ]
    delay_diff = [
        evidence[seed]["mean_censored_delay_s"]
        - static[seed]["mean_censored_delay_s"]
        for seed in common
    ]
    false_diff = [
        evidence[seed]["false_alarms_per_1000_clean_checks"]
        - static[seed]["false_alarms_per_1000_clean_checks"]
        for seed in common
    ]

    summary["paired_effect_vs_tuned_static"] = {
        "n_seeds": len(common),
        "event_recall_difference": statistics.mean(recall_diff),
        "event_recall_difference_ci95": paired_ci(
            recall_diff, seed=15016
        ),
        "delay_difference_s": statistics.mean(delay_diff),
        "delay_difference_ci95_s": paired_ci(
            delay_diff, seed=15017
        ),
        "false_alarm_difference_per_1000": statistics.mean(
            false_diff
        ),
        "false_alarm_difference_ci95_per_1000": paired_ci(
            false_diff, seed=15018
        ),
    }
    return summary


def markdown_report(summary, start_seed, n_seeds):
    effect = summary["paired_effect_vs_tuned_static"]
    lines = [
        "# Stage 15: hierarchical sequential evidence detector",
        "",
        (
            f"Held-out seeds: {start_seed}.."
            f"{start_seed + n_seeds - 1} ({n_seeds} paired worlds)."
        ),
        (
            "All detector variants receive the same passive samples and the "
            "same fixed four-CU-per-5-second schedule. Attack labels are used "
            "only by the evaluator."
        ),
        "",
        "| Detector | Event recall | Mean censored delay (s) | "
        "False alarms / 1000 clean checks | Alarm precision | "
        "Checked-sample F1 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for detector in DETECTORS:
        item = summary[detector]
        lines.append(
            f"| {detector} | {item['event_recall']:.3f} | "
            f"{item['mean_censored_delay_s']:.1f} | "
            f"{item['false_alarms_per_1000_clean_checks']:.3f} | "
            f"{item['alarm_precision']:.3f} | "
            f"{item['checked_sample_f1']:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Paired held-out effect: hierarchical e-CUSUM minus tuned static",
            "",
            (
                f"- Event recall: **{effect['event_recall_difference']:+.3f}**, "
                f"95% paired seed-bootstrap CI "
                f"[{effect['event_recall_difference_ci95'][0]:+.3f}, "
                f"{effect['event_recall_difference_ci95'][1]:+.3f}]."
            ),
            (
                f"- Mean censored delay: "
                f"**{effect['delay_difference_s']:+.1f} s**, "
                f"95% CI [{effect['delay_difference_ci95_s'][0]:+.1f}, "
                f"{effect['delay_difference_ci95_s'][1]:+.1f}]."
            ),
            (
                f"- False alarms / 1000 clean checks: "
                f"**{effect['false_alarm_difference_per_1000']:+.3f}**, "
                f"95% CI "
                f"[{effect['false_alarm_difference_ci95_per_1000'][0]:+.3f}, "
                f"{effect['false_alarm_difference_ci95_per_1000'][1]:+.3f}]."
            ),
            "",
            "## Interpretation",
            "",
            (
                "Primary endpoints are event recall, detection delay, and "
                "false-alarm frequency. Checked-sample F1 is reported for "
                "continuity with earlier stages but is not a fair primary "
                "score for a change detector that intentionally emits sparse "
                "event alarms rather than labeling every attacked sample."
            ),
            (
                "The static comparator is stronger than the original legacy "
                "rule: its three thresholds were selected only on tuning "
                "seeds 1001..1020. Stage-15 evidence parameters were likewise "
                "frozen before the held-out block beginning at seed 2001."
            ),
            (
                "These results establish superiority only inside this "
                "synthetic model. They do not establish production accuracy, "
                "formal e-process validity under dependent traffic, or novelty "
                "relative to all published detectors."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start-seed",
        type=int,
        default=DEFAULT_START_SEED,
    )
    parser.add_argument(
        "--seeds",
        type=int,
        default=DEFAULT_SEEDS,
    )
    parser.add_argument(
        "--output",
        default="stage15_results",
    )
    args = parser.parse_args()
    if args.seeds < 2:
        parser.error("At least two paired seeds required")

    seeds = range(args.start_seed, args.start_seed + args.seeds)
    rows = run(seeds)
    summary = summarize(rows)

    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    with (root / "runs.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(rows[0].keys()),
        )
        writer.writeheader()
        writer.writerows(rows)
    (root / "runs.json").write_text(
        json.dumps(rows, indent=2),
        encoding="utf8",
    )
    (root / "summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf8",
    )
    report = markdown_report(
        summary, args.start_seed, args.seeds
    )
    (root / "REPORT.md").write_text(report, encoding="utf8")
    print(report)


if __name__ == "__main__":
    main()
