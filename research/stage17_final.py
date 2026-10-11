"""Stage-17 final untouched evaluation.

IMPORTANT: parameters in this file are frozen from development seeds
6001..6040. This module performs no model selection or tuning.

Final evaluation block: seeds 7001..7200.
Historical Stage-16 evaluation seeds 5001..5200 are not reused.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import random
import statistics

from .stage16_detectors import (
    PageHinkleyConfig,
    PageHinkleyDetector,
)
from .stage16_eval import evaluate_detector
from .stage16_simulation import (
    BOUNDARY_KIND,
    PRIMARY_KINDS,
    WorldOOD,
)
from .stage17_detector import (
    DirectionalEConfig,
    DirectionalEProcessDetector,
)

FINAL_START_SEED = 7001
FINAL_SEEDS = 200

# Frozen after development on seeds 6001..6040.
FROZEN_DIRECTIONAL = DirectionalEConfig(
    decay=0.90,
    reference=0.12,
    threshold=5.0,
    direction_gate_p=0.06,
)

# Strong comparator independently retuned on the same development block.
FROZEN_PAGE_HINKLEY = PageHinkleyConfig(
    delta=0.50,
    threshold=8.0,
    integrity_gate_p=0.08,
    mean_alpha=0.10,
)

DETECTORS = (
    "page_hinkley_dev_frozen",
    "directional_e_process_frozen",
)


def paired_ci(differences, *, seed=17017, n_boot=5000):
    rng = random.Random(seed)
    n = len(differences)
    values = sorted(
        statistics.mean(
            differences[rng.randrange(n)]
            for _ in range(n)
        )
        for _ in range(n_boot)
    )
    return [
        values[int(0.025 * (n_boot - 1))],
        values[int(0.975 * (n_boot - 1))],
    ]


def run_seed(seed):
    world = WorldOOD(seed)
    variants = (
        (
            "page_hinkley_dev_frozen",
            PageHinkleyDetector(
                world, FROZEN_PAGE_HINKLEY
            ),
        ),
        (
            "directional_e_process_frozen",
            DirectionalEProcessDetector(
                world, FROZEN_DIRECTIONAL
            ),
        ),
    )
    rows = []
    for name, detector in variants:
        result = evaluate_detector(world, detector)
        result["detector"] = name
        rows.append(result)
    return rows


def run(seeds):
    rows = []
    for seed in seeds:
        rows.extend(run_seed(seed))
    return rows


def mean_or_none(values):
    values = [v for v in values if v is not None]
    return statistics.mean(values) if values else None


def summarize_detector(rows):
    return {
        "primary_event_recall": statistics.mean(
            row["primary_event_recall"] for row in rows
        ),
        "primary_horizon_penalized_delay_s": statistics.mean(
            row["primary_horizon_penalized_delay_s"]
            for row in rows
        ),
        "primary_normalized_delay": statistics.mean(
            row["primary_normalized_delay"] for row in rows
        ),
        "primary_detected_delay_s": mean_or_none(
            [
                row["primary_detected_delay_s"]
                for row in rows
            ]
        ),
        "false_alarms_per_1000_clean_checks": statistics.mean(
            row["false_alarms_per_1000_clean_checks"]
            for row in rows
        ),
        "boundary_event_recall": statistics.mean(
            row["boundary_event_recall"] for row in rows
        ),
        "probes": statistics.mean(
            row["probes"] for row in rows
        ),
        "per_kind": {
            kind: {
                "event_recall": statistics.mean(
                    row["per_kind"][kind]["event_recall"]
                    for row in rows
                ),
                "mean_horizon_penalized_delay_s": statistics.mean(
                    row["per_kind"][kind][
                        "mean_horizon_penalized_delay_s"
                    ]
                    for row in rows
                ),
            }
            for kind in (*PRIMARY_KINDS, BOUNDARY_KIND)
        },
    }


def paired_effect(rows):
    directional = {
        row["seed"]: row
        for row in rows
        if row["detector"]
        == "directional_e_process_frozen"
    }
    page = {
        row["seed"]: row
        for row in rows
        if row["detector"]
        == "page_hinkley_dev_frozen"
    }
    common = sorted(set(directional) & set(page))

    def differences(key):
        return [
            directional[seed][key] - page[seed][key]
            for seed in common
        ]

    recall = differences("primary_event_recall")
    delay = differences(
        "primary_horizon_penalized_delay_s"
    )
    normalized = differences(
        "primary_normalized_delay"
    )
    false_alarm = differences(
        "false_alarms_per_1000_clean_checks"
    )

    return {
        "n_seeds": len(common),
        "event_recall_difference": statistics.mean(
            recall
        ),
        "event_recall_difference_ci95": paired_ci(
            recall, seed=17018
        ),
        "horizon_penalized_delay_difference_s": (
            statistics.mean(delay)
        ),
        "horizon_penalized_delay_difference_ci95_s": (
            paired_ci(delay, seed=17019)
        ),
        "normalized_delay_difference": statistics.mean(
            normalized
        ),
        "normalized_delay_difference_ci95": paired_ci(
            normalized, seed=17020
        ),
        "false_alarm_difference_per_1000": (
            statistics.mean(false_alarm)
        ),
        "false_alarm_difference_ci95_per_1000": (
            paired_ci(false_alarm, seed=17021)
        ),
    }


def summarize(rows):
    summary = {
        "protocol": {
            "development_block": [6001, 6040],
            "historical_stage16_eval_forbidden": [
                5001, 5200
            ],
            "final_block": [7001, 7200],
            "final_parameters_frozen_before_run": True,
            "directional_config": dict(
                FROZEN_DIRECTIONAL.__dict__
            ),
            "page_hinkley_config": dict(
                FROZEN_PAGE_HINKLEY.__dict__
            ),
        },
        "detectors": {},
    }
    for name in DETECTORS:
        summary["detectors"][name] = summarize_detector(
            [
                row
                for row in rows
                if row["detector"] == name
            ]
        )
    summary["paired_effect_directional_minus_page_hinkley"] = (
        paired_effect(rows)
    )
    return summary


def markdown_report(summary, start_seed, n_seeds):
    page = summary["detectors"][
        "page_hinkley_dev_frozen"
    ]
    directional = summary["detectors"][
        "directional_e_process_frozen"
    ]
    effect = summary[
        "paired_effect_directional_minus_page_hinkley"
    ]

    lines = [
        "# Stage 17 final untouched evaluation",
        "",
        (
            f"Final seeds: {start_seed}.."
            f"{start_seed + n_seeds - 1} "
            f"({n_seeds} matched worlds)."
        ),
        (
            "Both detector configurations were frozen from "
            "development seeds 6001..6040 before this block ran."
        ),
        "",
        "| Detector | Primary recall | Horizon-penalized delay (s) | "
        "Normalized delay | False alarms / 1000 clean checks | "
        "Boundary recall |",
        "|---|---:|---:|---:|---:|---:|",
        (
            "| page_hinkley_dev_frozen | "
            f"{page['primary_event_recall']:.3f} | "
            f"{page['primary_horizon_penalized_delay_s']:.1f} | "
            f"{page['primary_normalized_delay']:.3f} | "
            f"{page['false_alarms_per_1000_clean_checks']:.3f} | "
            f"{page['boundary_event_recall']:.3f} |"
        ),
        (
            "| directional_e_process_frozen | "
            f"{directional['primary_event_recall']:.3f} | "
            f"{directional['primary_horizon_penalized_delay_s']:.1f} | "
            f"{directional['primary_normalized_delay']:.3f} | "
            f"{directional['false_alarms_per_1000_clean_checks']:.3f} | "
            f"{directional['boundary_event_recall']:.3f} |"
        ),
        "",
        "## Paired final effect: directional e-process minus Page-Hinkley",
        "",
        (
            f"- Event recall: **{effect['event_recall_difference']:+.3f}**, "
            "95% paired seed-bootstrap CI "
            f"[{effect['event_recall_difference_ci95'][0]:+.3f}, "
            f"{effect['event_recall_difference_ci95'][1]:+.3f}]."
        ),
        (
            f"- Horizon-penalized delay: "
            f"**{effect['horizon_penalized_delay_difference_s']:+.1f} s**, "
            "95% CI "
            f"[{effect['horizon_penalized_delay_difference_ci95_s'][0]:+.1f}, "
            f"{effect['horizon_penalized_delay_difference_ci95_s'][1]:+.1f}]."
        ),
        (
            f"- False alarms / 1000 clean checks: "
            f"**{effect['false_alarm_difference_per_1000']:+.3f}**, "
            "95% CI "
            f"[{effect['false_alarm_difference_ci95_per_1000'][0]:+.3f}, "
            f"{effect['false_alarm_difference_ci95_per_1000'][1]:+.3f}]."
        ),
        "",
        "## Per-primary-family recall",
        "",
        "| Detector | micro_step | reverse_step | nonlinear_ramp | sparse_bursts |",
        "|---|---:|---:|---:|---:|",
    ]

    for name, item in (
        ("page_hinkley_dev_frozen", page),
        ("directional_e_process_frozen", directional),
    ):
        pk = item["per_kind"]
        lines.append(
            f"| {name} | "
            f"{pk['micro_step']['event_recall']:.3f} | "
            f"{pk['reverse_step']['event_recall']:.3f} | "
            f"{pk['slow_nonlinear_ramp']['event_recall']:.3f} | "
            f"{pk['sparse_bursts']['event_recall']:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Guardrails",
            "",
            (
                "No final-seed tuning or threshold selection is performed. "
                "A miss receives its attack-window duration as the "
                "horizon-penalized delay."
            ),
            (
                "observer_silent_semantic remains outside the primary "
                "integrity-observer threat model and is reported separately."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def flatten(row):
    return {
        key: value
        for key, value in row.items()
        if key != "per_kind"
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start-seed",
        type=int,
        default=FINAL_START_SEED,
    )
    parser.add_argument(
        "--seeds",
        type=int,
        default=FINAL_SEEDS,
    )
    parser.add_argument(
        "--output",
        default="stage17_final_results",
    )
    args = parser.parse_args()

    if (
        args.start_seed != FINAL_START_SEED
        or args.seeds != FINAL_SEEDS
    ):
        raise SystemExit(
            "Stage17 final protocol is frozen to seeds "
            "7001..7200 (200 worlds)"
        )

    rows = run(
        range(args.start_seed, args.start_seed + args.seeds)
    )
    summary = summarize(rows)

    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)

    records = [flatten(row) for row in rows]
    with (root / "runs.csv").open(
        "w", newline=""
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(records[0].keys()),
        )
        writer.writeheader()
        writer.writerows(records)

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
    (root / "REPORT.md").write_text(
        report, encoding="utf8"
    )
    print(report)


if __name__ == "__main__":
    main()
