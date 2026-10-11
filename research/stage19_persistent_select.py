"""Development-only selector for the Stage-19 sustained-sign channel."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics

from .stage15_detector import upper_tail_rank
from .stage17_detector import lower_tail_rank
from .stage19_develop import (
    DEV_SEEDS,
    DEV_START_SEED,
    clean_tick_set,
    event_metrics,
)
from .stage19_detector import (
    RAW_SUSTAINED_GRID,
    robust_center_scale,
)
from .stage19_simulation import (
    WARMUP_TICKS,
    SparseIntegrityWorld,
)

FALSE_ALARM_CEILING = 0.50


def evaluate(world, config):
    calibration = world.values[:WARMUP_TICKS]
    center, scale = robust_center_scale(calibration)
    calibration_z = [
        (value - center) / scale
        for value in calibration
    ]
    positive = []
    negative = []
    alerts = set()
    clean = clean_tick_set(world)
    false = 0

    for tick in range(WARMUP_TICKS, world.total_ticks):
        z = (world.values[tick] - center) / scale
        p_positive = upper_tail_rank(calibration_z, z)
        p_negative = lower_tail_rank(calibration_z, z)

        floor = tick - config.window + 1
        positive = [item for item in positive if item >= floor]
        negative = [item for item in negative if item >= floor]

        positive_hit = (
            z >= config.magnitude_gate_z
            and p_positive <= config.tail_gate_p
        )
        negative_hit = (
            z <= -config.magnitude_gate_z
            and p_negative <= config.tail_gate_p
        )
        if positive_hit:
            positive.append(tick)
            negative = []
        elif negative_hit:
            negative.append(tick)
            positive = []

        alarm = (
            positive_hit and len(positive) >= config.hits
        ) or (
            negative_hit and len(negative) >= config.hits
        )
        if alarm:
            alerts.add(tick)
            false += int(tick in clean)
            positive = []
            negative = []

    return event_metrics(
        world, alerts, false, len(clean)
    )


def summarize(rows):
    keys = (
        "event_recall",
        "sparse_event_recall",
        "persistent_event_recall",
        "horizon_penalized_delay_ticks",
        "sparse_horizon_penalized_delay_ticks",
        "false_alarms_per_1000_clean_ticks",
    )
    return {
        key: statistics.mean(row[key] for row in rows)
        for key in keys
    }


def select():
    worlds = [
        SparseIntegrityWorld(seed)
        for seed in range(
            DEV_START_SEED,
            DEV_START_SEED + DEV_SEEDS,
        )
    ]
    candidates = []
    for config in RAW_SUSTAINED_GRID:
        rows = [evaluate(world, config) for world in worlds]
        candidates.append(
            {
                "config": dict(config.__dict__),
                "summary": summarize(rows),
            }
        )

    feasible = [
        item for item in candidates
        if item["summary"]["false_alarms_per_1000_clean_ticks"]
        <= FALSE_ALARM_CEILING
    ]
    pool = feasible or candidates
    if feasible:
        best = max(
            pool,
            key=lambda item: (
                item["summary"]["persistent_event_recall"],
                item["summary"]["event_recall"],
                -item["summary"]["horizon_penalized_delay_ticks"],
                -item["summary"][
                    "false_alarms_per_1000_clean_ticks"
                ],
            ),
        )
    else:
        best = min(
            pool,
            key=lambda item: (
                item["summary"][
                    "false_alarms_per_1000_clean_ticks"
                ],
                -item["summary"]["persistent_event_recall"],
            ),
        )

    return {
        "protocol": {
            "development_block": [9001, 9040],
            "final_or_stage18_data_used": False,
            "false_alarm_ceiling_per_1000": 0.50,
        },
        "grid_size": len(RAW_SUSTAINED_GRID),
        "selected": best,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage19_persistent_selection.json",
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
