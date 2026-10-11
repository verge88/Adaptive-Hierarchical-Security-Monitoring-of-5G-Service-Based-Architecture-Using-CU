"""Reproducible tuning of strong Stage-16 comparison detectors.

Only classic baselines are tuned here.  The hierarchical e-CUSUM imported from
Stage 15 remains completely frozen.

Selection rule:
1. use tuning seeds 4001..4024 only;
2. retain configurations with mean false alarms <= 0.50 / 1000 clean checks;
3. among feasible configurations maximize primary event recall;
4. break ties by lower horizon-penalized delay, then lower false alarms.
If no configuration satisfies the false-alarm ceiling, choose the lowest
false-alarm configuration and break ties by recall/delay.

The full grid summary is written to JSON so the choice is auditable.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics

from .stage16_detectors import (
    CUSUM_GRID,
    EWMA_GRID,
    PAGE_HINKLEY_GRID,
    STATIC_GRID,
    config_to_dict,
    detector_from_config,
)
from .stage16_eval import evaluate_detector
from .stage16_simulation import WorldOOD

TUNE_START_SEED = 4001
TUNE_SEEDS = 24
FALSE_ALARM_CEILING = 0.50

FAMILIES = {
    "calibrated_static": STATIC_GRID,
    "ewma": EWMA_GRID,
    "cusum": CUSUM_GRID,
    "page_hinkley": PAGE_HINKLEY_GRID,
}


def summarize_rows(rows):
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
        "false_alarms_per_1000_clean_checks": statistics.mean(
            row["false_alarms_per_1000_clean_checks"]
            for row in rows
        ),
        "boundary_event_recall": statistics.mean(
            row["boundary_event_recall"] for row in rows
        ),
    }


def select_best(candidates):
    feasible = [
        item
        for item in candidates
        if item["summary"][
            "false_alarms_per_1000_clean_checks"
        ] <= FALSE_ALARM_CEILING
    ]
    if feasible:
        return max(
            feasible,
            key=lambda item: (
                item["summary"]["primary_event_recall"],
                -item["summary"][
                    "primary_horizon_penalized_delay_s"
                ],
                -item["summary"][
                    "false_alarms_per_1000_clean_checks"
                ],
            ),
        )
    return min(
        candidates,
        key=lambda item: (
            item["summary"][
                "false_alarms_per_1000_clean_checks"
            ],
            -item["summary"]["primary_event_recall"],
            item["summary"][
                "primary_horizon_penalized_delay_s"
            ],
        ),
    )


def tune(start_seed=TUNE_START_SEED, n_seeds=TUNE_SEEDS):
    seeds = list(range(start_seed, start_seed + n_seeds))
    worlds = [WorldOOD(seed) for seed in seeds]
    output = {
        "protocol": {
            "start_seed": start_seed,
            "n_seeds": n_seeds,
            "false_alarm_ceiling_per_1000": (
                FALSE_ALARM_CEILING
            ),
            "selection": (
                "maximize primary recall under false-alarm ceiling; "
                "then minimize horizon-penalized delay and false alarms"
            ),
            "stage15_e_cusum_frozen": True,
        },
        "families": {},
        "selected": {},
    }

    for name, grid in FAMILIES.items():
        candidates = []
        for config in grid:
            rows = []
            config_dict = config_to_dict(config)
            for world in worlds:
                detector = detector_from_config(
                    name, world, config_dict
                )
                rows.append(
                    evaluate_detector(world, detector)
                )
            candidates.append(
                {
                    "config": config_dict,
                    "summary": summarize_rows(rows),
                }
            )

        best = select_best(candidates)
        output["families"][name] = {
            "grid_size": len(grid),
            "candidates": candidates,
        }
        output["selected"][name] = best

    champion_candidates = [
        {
            "name": name,
            "config": item["config"],
            "summary": item["summary"],
        }
        for name, item in output["selected"].items()
    ]
    feasible = [
        item
        for item in champion_candidates
        if item["summary"][
            "false_alarms_per_1000_clean_checks"
        ] <= FALSE_ALARM_CEILING
    ]
    pool = feasible if feasible else champion_candidates
    output["baseline_champion"] = max(
        pool,
        key=lambda item: (
            item["summary"]["primary_event_recall"],
            -item["summary"][
                "primary_horizon_penalized_delay_s"
            ],
            -item["summary"][
                "false_alarms_per_1000_clean_checks"
            ],
        ),
    )
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start-seed",
        type=int,
        default=TUNE_START_SEED,
    )
    parser.add_argument(
        "--seeds",
        type=int,
        default=TUNE_SEEDS,
    )
    parser.add_argument(
        "--output",
        default="stage16_tuning.json",
    )
    args = parser.parse_args()
    if args.seeds < 4:
        parser.error("At least four tuning seeds required")

    result = tune(args.start_seed, args.seeds)
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )

    print("# Stage 16 baseline tuning")
    print(
        f"Seeds: {args.start_seed}.."
        f"{args.start_seed + args.seeds - 1}"
    )
    for name, item in result["selected"].items():
        summary = item["summary"]
        print(
            name,
            json.dumps(item["config"], sort_keys=True),
            f"recall={summary['primary_event_recall']:.3f}",
            (
                "delay="
                f"{summary['primary_horizon_penalized_delay_s']:.1f}s"
            ),
            (
                "fa/1000="
                f"{summary['false_alarms_per_1000_clean_checks']:.3f}"
            ),
        )


if __name__ == "__main__":
    main()
