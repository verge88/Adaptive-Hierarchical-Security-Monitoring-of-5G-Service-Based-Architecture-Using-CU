"""Stage-16 OOD benchmark for the frozen Stage-15 hierarchical e-CUSUM.

Classic baselines are tuned exclusively on Stage-16 tuning seeds.  Evaluation
seeds are disjoint and never influence detector selection.  The Stage-15
hierarchical e-CUSUM is imported unchanged.

Primary comparison is against the predeclared baseline champion selected on
the tuning block.  All individual baseline families are also reported.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import random
import statistics

from .stage15_detector import (
    HIERARCHICAL_E_CUSUM,
    HierarchicalECUSUMDetector,
)
from .stage16_detectors import detector_from_config
from .stage16_eval import evaluate_detector
from .stage16_simulation import (
    BOUNDARY_KIND,
    PRIMARY_KINDS,
    WorldOOD,
)

DEFAULT_START_SEED = 5001
DEFAULT_SEEDS = 200


def paired_ci(differences, *, seed=16016, n_boot=5000):
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


def build_variants(world, tuning):
    variants = []
    for name, item in tuning["selected"].items():
        variants.append(
            (
                name,
                detector_from_config(
                    name, world, item["config"]
                ),
            )
        )
    variants.append(
        (
            "hierarchical_e_cusum_frozen",
            HierarchicalECUSUMDetector(
                world, HIERARCHICAL_E_CUSUM
            ),
        )
    )
    return variants


def run(seeds, tuning):
    rows = []
    for seed in seeds:
        world = WorldOOD(seed)
        for name, detector in build_variants(
            world, tuning
        ):
            result = evaluate_detector(world, detector)
            result["detector"] = name
            rows.append(result)
    return rows


def mean_or_none(values):
    filtered = [
        value for value in values if value is not None
    ]
    return (
        statistics.mean(filtered)
        if filtered
        else None
    )


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
        "boundary_horizon_penalized_delay_s": statistics.mean(
            row["boundary_horizon_penalized_delay_s"]
            for row in rows
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
                "mean_normalized_delay": statistics.mean(
                    row["per_kind"][kind][
                        "mean_normalized_delay"
                    ]
                    for row in rows
                ),
            }
            for kind in (*PRIMARY_KINDS, BOUNDARY_KIND)
        },
    }


def pair_effect(rows, challenger, comparator):
    by_name = {}
    for name in (challenger, comparator):
        by_name[name] = {
            row["seed"]: row
            for row in rows
            if row["detector"] == name
        }
    common = sorted(
        set(by_name[challenger])
        & set(by_name[comparator])
    )

    recall = [
        by_name[challenger][seed][
            "primary_event_recall"
        ]
        - by_name[comparator][seed][
            "primary_event_recall"
        ]
        for seed in common
    ]
    delay = [
        by_name[challenger][seed][
            "primary_horizon_penalized_delay_s"
        ]
        - by_name[comparator][seed][
            "primary_horizon_penalized_delay_s"
        ]
        for seed in common
    ]
    false_alarm = [
        by_name[challenger][seed][
            "false_alarms_per_1000_clean_checks"
        ]
        - by_name[comparator][seed][
            "false_alarms_per_1000_clean_checks"
        ]
        for seed in common
    ]
    normalized = [
        by_name[challenger][seed][
            "primary_normalized_delay"
        ]
        - by_name[comparator][seed][
            "primary_normalized_delay"
        ]
        for seed in common
    ]

    return {
        "n_seeds": len(common),
        "challenger": challenger,
        "comparator": comparator,
        "event_recall_difference": statistics.mean(
            recall
        ),
        "event_recall_difference_ci95": paired_ci(
            recall, seed=16017
        ),
        "horizon_penalized_delay_difference_s": (
            statistics.mean(delay)
        ),
        "horizon_penalized_delay_difference_ci95_s": (
            paired_ci(delay, seed=16018)
        ),
        "normalized_delay_difference": statistics.mean(
            normalized
        ),
        "normalized_delay_difference_ci95": paired_ci(
            normalized, seed=16019
        ),
        "false_alarm_difference_per_1000": (
            statistics.mean(false_alarm)
        ),
        "false_alarm_difference_ci95_per_1000": (
            paired_ci(false_alarm, seed=16020)
        ),
    }


def summarize(rows, tuning):
    detectors = sorted(
        {row["detector"] for row in rows}
    )
    summary = {
        "protocol": {
            "evaluation_is_disjoint_from_tuning": True,
            "frozen_stage15_detector": True,
            "primary_attack_kinds": list(PRIMARY_KINDS),
            "boundary_attack_kind": BOUNDARY_KIND,
            "baseline_champion_selected_on_tuning_only": (
                tuning["baseline_champion"]["name"]
            ),
        },
        "detectors": {
            name: summarize_detector(
                [
                    row
                    for row in rows
                    if row["detector"] == name
                ]
            )
            for name in detectors
        },
    }

    champion = tuning["baseline_champion"]["name"]
    summary["primary_paired_effect"] = pair_effect(
        rows,
        "hierarchical_e_cusum_frozen",
        champion,
    )
    summary["paired_effects_all_baselines"] = {
        name: pair_effect(
            rows,
            "hierarchical_e_cusum_frozen",
            name,
        )
        for name in detectors
        if name != "hierarchical_e_cusum_frozen"
    }
    return summary


def markdown_report(
    summary, tuning, start_seed, n_seeds
):
    champion = tuning["baseline_champion"]["name"]
    lines = [
        "# Stage 16: OOD sequential-detector benchmark",
        "",
        (
            f"Evaluation seeds: {start_seed}.."
            f"{start_seed + n_seeds - 1} "
            f"({n_seeds} matched worlds)."
        ),
        (
            "Stage-15 hierarchical e-CUSUM parameters are frozen. "
            "Classic baselines were tuned only on the disjoint "
            "Stage-16 tuning block."
        ),
        (
            f"Predeclared baseline champion from tuning: "
            f"**{champion}**."
        ),
        "",
        "| Detector | Primary recall | Horizon-penalized delay (s) | "
        "Normalized delay | False alarms / 1000 clean checks | "
        "Boundary observer-silent recall |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    for name, item in summary["detectors"].items():
        lines.append(
            f"| {name} | "
            f"{item['primary_event_recall']:.3f} | "
            f"{item['primary_horizon_penalized_delay_s']:.1f} | "
            f"{item['primary_normalized_delay']:.3f} | "
            f"{item['false_alarms_per_1000_clean_checks']:.3f} | "
            f"{item['boundary_event_recall']:.3f} |"
        )

    effect = summary["primary_paired_effect"]
    lines.extend(
        [
            "",
            (
                "## Primary paired effect: frozen e-CUSUM minus "
                f"{champion}"
            ),
            "",
            (
                f"- Event recall: "
                f"**{effect['event_recall_difference']:+.3f}**, "
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
            "## Per-attack primary recall",
            "",
            "| Detector | micro_step | reverse_step | slow_ramp | sparse_bursts |",
            "|---|---:|---:|---:|---:|",
        ]
    )

    for name, item in summary["detectors"].items():
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
            "## Interpretation guardrails",
            "",
            (
                "A miss is assigned the duration of that attack window "
                "for the horizon-penalized delay. This is a penalty metric, "
                "not survival-analysis censoring."
            ),
            (
                "observer_silent_semantic is a boundary test outside the "
                "independent-integrity-observer assumption and is therefore "
                "not included in primary recall/delay."
            ),
            (
                "No detector is allowed to change the fixed CU schedule or "
                "probe budget. Attack labels are used only by the evaluator."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def flatten_row(row):
    return {
        key: value
        for key, value in row.items()
        if key != "per_kind"
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--tuning",
        default="stage16_tuning.json",
    )
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
        default="stage16_results",
    )
    args = parser.parse_args()
    if args.seeds < 10:
        parser.error(
            "At least ten OOD evaluation seeds required"
        )

    tuning = json.loads(
        Path(args.tuning).read_text(encoding="utf8")
    )
    seeds = range(
        args.start_seed,
        args.start_seed + args.seeds,
    )
    rows = run(seeds, tuning)
    summary = summarize(rows, tuning)

    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)

    records = [flatten_row(row) for row in rows]
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
    (root / "tuning.json").write_text(
        json.dumps(tuning, indent=2),
        encoding="utf8",
    )

    report = markdown_report(
        summary,
        tuning,
        args.start_seed,
        args.seeds,
    )
    (root / "REPORT.md").write_text(
        report, encoding="utf8"
    )
    print(report)


if __name__ == "__main__":
    main()
