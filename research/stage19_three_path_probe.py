"""Probe the union of three already-selected Stage-19 development channels.

No additional parameter search is performed here.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics

from .stage19_develop import clean_tick_set, event_metrics
from .stage19_detector import (
    AdaptiveConsecutiveConfig,
    AdaptiveConsecutiveDirectionalDetector,
    AdaptiveRobustSparseEScanConfig,
    AdaptiveRobustSparseEScanDetector,
    SingleScaleDirectionalConfig,
    SingleScaleDirectionalDetector,
)
from .stage19_simulation import (
    WARMUP_TICKS,
    SparseIntegrityWorld,
)

DEV_SEEDS = range(9001, 9041)

SPARSE_CONFIG = AdaptiveRobustSparseEScanConfig(
    windows=(16, 32, 64),
    tail_gate_p=0.07,
    magnitude_gate_z=3.5,
    min_hits=2,
    e_sum_threshold=2.2,
    center_alpha=0.03,
    scale_alpha=0.02,
)

SINGLE_CONFIG = SingleScaleDirectionalConfig(
    decay=0.90,
    reference=0.12,
    threshold=7.0,
    direction_gate_p=0.04,
)

CONSECUTIVE_CONFIG = AdaptiveConsecutiveConfig(
    window=5,
    hits=3,
    magnitude_gate_z=2.6,
    tail_gate_p=0.15,
    center_alpha=0.03,
    scale_alpha=0.02,
)


def evaluate(world):
    calibration = world.values[:WARMUP_TICKS]
    sparse = AdaptiveRobustSparseEScanDetector(
        calibration, SPARSE_CONFIG
    )
    single = SingleScaleDirectionalDetector(
        calibration, SINGLE_CONFIG
    )
    consecutive = AdaptiveConsecutiveDirectionalDetector(
        calibration, CONSECUTIVE_CONFIG
    )

    alerts = set()
    clean = clean_tick_set(world)
    for tick in range(WARMUP_TICKS, world.total_ticks):
        value = world.values[tick]
        sparse_alarm, _ = sparse.observe(value)
        single_alarm, _ = single.observe(value)
        consecutive_alarm, _ = consecutive.observe(value)
        if sparse_alarm or single_alarm or consecutive_alarm:
            alerts.add(tick)

    false = len(alerts & clean)
    return event_metrics(
        world, alerts, false, len(clean)
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage19_three_path_probe.json",
    )
    args = parser.parse_args()

    rows = [
        evaluate(SparseIntegrityWorld(seed))
        for seed in DEV_SEEDS
    ]
    keys = (
        "event_recall",
        "sparse_event_recall",
        "persistent_event_recall",
        "horizon_penalized_delay_ticks",
        "sparse_horizon_penalized_delay_ticks",
        "false_alarms_per_1000_clean_ticks",
    )
    summary = {
        key: statistics.mean(row[key] for row in rows)
        for key in keys
    }
    result = {
        "protocol": {
            "development_block": [9001, 9040],
            "parameter_search_in_this_probe": False,
            "final_or_stage18_data_used": False,
            "false_alarm_ceiling_per_1000": 0.50,
            "persistent_recall_floor": 0.90,
        },
        "sparse_config": dict(SPARSE_CONFIG.__dict__),
        "single_config": dict(SINGLE_CONFIG.__dict__),
        "consecutive_config": dict(CONSECUTIVE_CONFIG.__dict__),
        "summary": summary,
        "passes_predeclared_gate": (
            summary["false_alarms_per_1000_clean_ticks"] <= 0.50
            and summary["persistent_event_recall"] >= 0.90
        ),
    }
    result["sparse_config"]["windows"] = list(
        result["sparse_config"]["windows"]
    )
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
