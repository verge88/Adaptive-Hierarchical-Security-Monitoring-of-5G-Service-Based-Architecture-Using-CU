"""Fast Stage-19 sparse-plus-persistent fusion selector.

Searches only the new fusion grid on development seeds 9001..9040.  Strong
single-scale and Page-Hinkley comparators remain fixed from their earlier
selection on the same development block.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage19_develop import (
    DEV_SEEDS,
    DEV_START_SEED,
    build_trace,
    evaluate_page_hinkley,
    evaluate_single,
    evaluate_sparse_plus_directional,
    select_best,
    summarize,
)
from .stage19_detector import (
    SPARSE_PLUS_DIRECTIONAL_GRID,
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


def select_fusion():
    worlds = [
        SparseIntegrityWorld(seed)
        for seed in range(
            DEV_START_SEED,
            DEV_START_SEED + DEV_SEEDS,
        )
    ]
    traces = [build_trace(world) for world in worlds]

    candidates = []
    for config in SPARSE_PLUS_DIRECTIONAL_GRID:
        rows = [
            evaluate_sparse_plus_directional(
                world, trace, config
            )
            for world, trace in zip(worlds, traces)
        ]
        cfg = dict(config.__dict__)
        cfg["sparse_windows"] = list(
            cfg["sparse_windows"]
        )
        candidates.append(
            {
                "config": cfg,
                "summary": summarize(rows),
            }
        )
    selected = select_best(candidates)

    single = summarize(
        [
            evaluate_single(world, trace, SELECTED_SINGLE)
            for world, trace in zip(worlds, traces)
        ]
    )
    page = summarize(
        [
            evaluate_page_hinkley(world, trace, SELECTED_PAGE)
            for world, trace in zip(worlds, traces)
        ]
    )

    return {
        "protocol": {
            "development_block": [9001, 9040],
            "stage18_live_artifacts_used": False,
            "stage19_final_block_used": False,
            "false_alarm_ceiling_per_1000": 0.50,
            "persistent_recall_floor": 0.90,
        },
        "fusion_grid_size": len(
            SPARSE_PLUS_DIRECTIONAL_GRID
        ),
        "selected_fusion": selected,
        "fixed_comparator_single_scale": {
            "config": dict(SELECTED_SINGLE.__dict__),
            "summary": single,
        },
        "fixed_comparator_page_hinkley": {
            "config": dict(SELECTED_PAGE.__dict__),
            "summary": page,
        },
        "fusion_minus_single": {
            key: selected["summary"][key] - single[key]
            for key in selected["summary"]
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage19_fusion_selection.json",
    )
    args = parser.parse_args()
    result = select_fusion()
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
