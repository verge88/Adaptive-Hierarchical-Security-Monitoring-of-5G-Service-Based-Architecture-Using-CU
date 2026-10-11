"""Fast Stage-19 dual-path development selector.

Previous development runs already selected the strongest single-scale and
Page-Hinkley configurations on exactly the same seeds 9001..9040.  This module
re-evaluates those fixed comparators and searches only the new dual-path grid,
avoiding repeated computation of rejected detector families.

No final or Stage-18 live data is read.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage19_develop import (
    DEV_SEEDS,
    DEV_START_SEED,
    build_trace,
    evaluate_dual_path,
    evaluate_page_hinkley,
    evaluate_single,
    select_best,
    summarize,
)
from .stage19_detector import (
    DUAL_PATH_GRID,
    ScalarPageHinkleyConfig,
    SingleScaleDirectionalConfig,
)
from .stage19_simulation import SparseIntegrityWorld

SELECTED_SINGLE = SingleScaleDirectionalConfig(
    decay=0.90,
    reference=0.12,
    threshold=7.0,
    direction_gate_p=0.04,
)

SELECTED_PAGE = ScalarPageHinkleyConfig(
    delta=0.30,
    threshold=5.0,
    gate_p=0.08,
    mean_alpha=0.20,
)


def select_dual(
    start_seed: int = DEV_START_SEED,
    n_seeds: int = DEV_SEEDS,
):
    if start_seed != DEV_START_SEED or n_seeds != DEV_SEEDS:
        raise ValueError(
            "Fast selector is frozen to development seeds 9001..9040"
        )

    worlds = [
        SparseIntegrityWorld(seed)
        for seed in range(start_seed, start_seed + n_seeds)
    ]
    traces = [build_trace(world) for world in worlds]

    candidates = []
    for config in DUAL_PATH_GRID:
        rows = [
            evaluate_dual_path(world, trace, config)
            for world, trace in zip(worlds, traces)
        ]
        candidates.append(
            {
                "config": dict(config.__dict__),
                "summary": summarize(rows),
            }
        )
    selected = select_best(candidates)

    single_rows = [
        evaluate_single(world, trace, SELECTED_SINGLE)
        for world, trace in zip(worlds, traces)
    ]
    page_rows = [
        evaluate_page_hinkley(world, trace, SELECTED_PAGE)
        for world, trace in zip(worlds, traces)
    ]
    single = summarize(single_rows)
    page = summarize(page_rows)

    return {
        "protocol": {
            "development_block": [9001, 9040],
            "stage18_live_artifacts_used": False,
            "final_block_used": False,
            "false_alarm_ceiling_per_1000": 0.50,
            "persistent_recall_floor": 0.90,
        },
        "dual_grid_size": len(DUAL_PATH_GRID),
        "selected_dual_path": selected,
        "fixed_comparator_single_scale": {
            "config": dict(SELECTED_SINGLE.__dict__),
            "summary": single,
        },
        "fixed_comparator_page_hinkley": {
            "config": dict(SELECTED_PAGE.__dict__),
            "summary": page,
        },
        "dual_minus_single": {
            key: selected["summary"][key] - single[key]
            for key in selected["summary"]
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage19_dual_selection.json",
    )
    args = parser.parse_args()
    result = select_dual()
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
