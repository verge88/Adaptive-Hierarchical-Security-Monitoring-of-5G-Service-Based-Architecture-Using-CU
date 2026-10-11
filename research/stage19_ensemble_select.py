"""Stage-19 Pareto allocation of the false-alarm budget across channels.

All work is development-only (9001..9040). No new detector mechanism or final
data is introduced. For each existing channel family we select its best config
under several individual FA ceilings, then evaluate only the small Cartesian
product of those Pareto representatives as an OR ensemble.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics

from .stage19_consecutive_select import evaluate as evaluate_consecutive
from .stage19_develop import (
    build_trace,
    clean_tick_set,
    event_metrics,
    evaluate_adaptive_robust_sparse_scan,
    evaluate_single,
    summarize,
)
from .stage19_detector import (
    ADAPTIVE_CONSECUTIVE_GRID,
    ADAPTIVE_ROBUST_SCAN_GRID,
    SINGLE_SCALE_GRID,
    AdaptiveConsecutiveDirectionalDetector,
    AdaptiveRobustSparseEScanDetector,
    SingleScaleDirectionalDetector,
)
from .stage19_simulation import WARMUP_TICKS, SparseIntegrityWorld

DEV_SEEDS = tuple(range(9001, 9041))
BUDGET_LEVELS = (0.0, 0.14, 0.27, 0.40, 0.50)
TOTAL_FA_CEILING = 0.50
PERSISTENT_RECALL_FLOOR = 0.90


def _best_at_budgets(candidates, target_key):
    selected = []
    seen = set()
    for budget in BUDGET_LEVELS:
        feasible = [
            item for item in candidates
            if item["summary"]["false_alarms_per_1000_clean_ticks"]
            <= budget + 1e-12
        ]
        if not feasible:
            continue
        best = max(
            feasible,
            key=lambda item: (
                item["summary"][target_key],
                item["summary"]["event_recall"],
                -item["summary"]["horizon_penalized_delay_ticks"],
                -item["summary"]["false_alarms_per_1000_clean_ticks"],
            ),
        )
        key = json.dumps(best["config"], sort_keys=True)
        if key not in seen:
            seen.add(key)
            selected.append(best)
    return selected


def _config_dict(config):
    data = dict(config.__dict__)
    if "windows" in data:
        data["windows"] = list(data["windows"])
    return data


def _alarm_set(world, config, family):
    calibration = world.values[:WARMUP_TICKS]
    if family == "sparse":
        detector = AdaptiveRobustSparseEScanDetector(
            calibration, config
        )
    elif family == "single":
        detector = SingleScaleDirectionalDetector(
            calibration, config
        )
    elif family == "consecutive":
        detector = AdaptiveConsecutiveDirectionalDetector(
            calibration, config
        )
    else:
        raise ValueError(family)

    alerts = set()
    for tick in range(WARMUP_TICKS, world.total_ticks):
        alarm, _ = detector.observe(world.values[tick])
        if alarm:
            alerts.add(tick)
    return alerts


def _ensemble_metrics(world, sparse_cfg, single_cfg, consecutive_cfg):
    alerts = (
        _alarm_set(world, sparse_cfg, "sparse")
        | _alarm_set(world, single_cfg, "single")
        | _alarm_set(world, consecutive_cfg, "consecutive")
    )
    clean = clean_tick_set(world)
    return event_metrics(
        world,
        alerts,
        len(alerts & clean),
        len(clean),
    )


def select():
    worlds = [SparseIntegrityWorld(seed) for seed in DEV_SEEDS]
    traces = [build_trace(world) for world in worlds]

    sparse_candidates = []
    for config in ADAPTIVE_ROBUST_SCAN_GRID:
        rows = [
            evaluate_adaptive_robust_sparse_scan(
                world, trace, config
            )
            for world, trace in zip(worlds, traces)
        ]
        sparse_candidates.append(
            {
                "config": _config_dict(config),
                "object": config,
                "summary": summarize(rows),
            }
        )

    single_candidates = []
    for config in SINGLE_SCALE_GRID:
        rows = [
            evaluate_single(world, trace, config)
            for world, trace in zip(worlds, traces)
        ]
        single_candidates.append(
            {
                "config": _config_dict(config),
                "object": config,
                "summary": summarize(rows),
            }
        )

    consecutive_candidates = []
    for config in ADAPTIVE_CONSECUTIVE_GRID:
        rows = [evaluate_consecutive(world, config) for world in worlds]
        consecutive_candidates.append(
            {
                "config": _config_dict(config),
                "object": config,
                "summary": summarize(rows),
            }
        )

    sparse_front = _best_at_budgets(
        sparse_candidates, "sparse_event_recall"
    )
    single_front = _best_at_budgets(
        single_candidates, "persistent_event_recall"
    )
    consecutive_front = _best_at_budgets(
        consecutive_candidates, "persistent_event_recall"
    )

    combinations = []
    for sparse in sparse_front:
        for single in single_front:
            for consecutive in consecutive_front:
                rows = [
                    _ensemble_metrics(
                        world,
                        sparse["object"],
                        single["object"],
                        consecutive["object"],
                    )
                    for world in worlds
                ]
                combinations.append(
                    {
                        "sparse": sparse["config"],
                        "single": single["config"],
                        "consecutive": consecutive["config"],
                        "summary": summarize(rows),
                    }
                )

    feasible = [
        item for item in combinations
        if item["summary"]["false_alarms_per_1000_clean_ticks"]
        <= TOTAL_FA_CEILING
        and item["summary"]["persistent_event_recall"]
        >= PERSISTENT_RECALL_FLOOR
    ]
    if feasible:
        best = max(
            feasible,
            key=lambda item: (
                item["summary"]["sparse_event_recall"],
                item["summary"]["persistent_event_recall"],
                item["summary"]["event_recall"],
                -item["summary"]["horizon_penalized_delay_ticks"],
                -item["summary"]["false_alarms_per_1000_clean_ticks"],
            ),
        )
    else:
        best = None

    def public_front(front):
        return [
            {
                "config": item["config"],
                "summary": item["summary"],
            }
            for item in front
        ]

    return {
        "protocol": {
            "development_block": [9001, 9040],
            "final_or_stage18_data_used": False,
            "total_false_alarm_ceiling_per_1000": TOTAL_FA_CEILING,
            "persistent_recall_floor": PERSISTENT_RECALL_FLOOR,
            "individual_budget_levels": list(BUDGET_LEVELS),
        },
        "pareto_fronts": {
            "sparse": public_front(sparse_front),
            "single": public_front(single_front),
            "consecutive": public_front(consecutive_front),
        },
        "combination_count": len(combinations),
        "selected_ensemble": best,
        "passes_predeclared_gate": best is not None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage19_ensemble_selection.json",
    )
    args = parser.parse_args()
    result = select()
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
