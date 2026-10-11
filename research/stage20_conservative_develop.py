"""Stage 20 conservative mixed-regime structural development.

The first Stage-20 stress block (20001..20080) is inspected and is not reused.

Fresh blocks:
- stable tuning:            21001..21040
- unstable tuning:          21101..21140
- stable validation:        22001..22120
- unstable stress:          23001..23080

Selection requires ZERO false alarms across BOTH stable and unstable tuning
worlds. Recall/delay optimization is then performed on stable worlds only,
because the structural channel is intentionally allowed to disable itself when
warm-up schema agreement is not sufficiently stable.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage20_develop import (
    StructuralWorld,
    evaluate_block,
)
from .stage20_structure import StructuralQuorumConfig

STABLE_TUNE_START = 21001
STABLE_TUNE_SEEDS = 40
UNSTABLE_TUNE_START = 21101
UNSTABLE_TUNE_SEEDS = 40
VALID_START = 22001
VALID_SEEDS = 120
STRESS_START = 23001
STRESS_SEEDS = 80
FINAL_FA_CEILING = 0.50

CONSERVATIVE_GRID = tuple(
    StructuralQuorumConfig(
        stability_fraction_threshold=stability,
        window_ticks=window,
        required_hits=hits,
        min_token_difference=min_diff,
        large_difference_tokens=large,
    )
    for stability in (0.98, 1.00)
    for window in (12, 16, 20)
    for hits in (2, 3, 4)
    for min_diff in (1, 2)
    for large in (8, 12)
)


def select(candidates):
    feasible = [
        item
        for item in candidates
        if (
            item["stable_tuning"]["false_alarms_per_1000"] == 0.0
            and item["unstable_tuning"]["false_alarms_per_1000"] == 0.0
        )
    ]
    if not feasible:
        raise AssertionError(
            "No Stage20 config achieved zero FA on both tuning regimes"
        )

    return max(
        feasible,
        key=lambda item: (
            item["stable_tuning"]["min_family_recall"],
            item["stable_tuning"]["event_recall"],
            -item["stable_tuning"]["mean_horizon_penalized_delay"],
            -item["unstable_tuning"]["enabled_fraction"],
        ),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage20_conservative_development.json",
    )
    args = parser.parse_args()

    stable_tuning = [
        StructuralWorld(seed)
        for seed in range(
            STABLE_TUNE_START,
            STABLE_TUNE_START + STABLE_TUNE_SEEDS,
        )
    ]
    unstable_tuning = [
        StructuralWorld(seed, unstable_schema=True)
        for seed in range(
            UNSTABLE_TUNE_START,
            UNSTABLE_TUNE_START + UNSTABLE_TUNE_SEEDS,
        )
    ]

    candidates = []
    for config in CONSERVATIVE_GRID:
        candidates.append(
            {
                "config": dict(config.__dict__),
                "stable_tuning": evaluate_block(
                    stable_tuning, config
                ),
                "unstable_tuning": evaluate_block(
                    unstable_tuning, config
                ),
            }
        )

    selected = select(candidates)
    config = StructuralQuorumConfig(
        **selected["config"]
    )

    validation = evaluate_block(
        [
            StructuralWorld(seed)
            for seed in range(
                VALID_START,
                VALID_START + VALID_SEEDS,
            )
        ],
        config,
    )
    stress = evaluate_block(
        [
            StructuralWorld(seed, unstable_schema=True)
            for seed in range(
                STRESS_START,
                STRESS_START + STRESS_SEEDS,
            )
        ],
        config,
    )

    if validation["false_alarms_per_1000"] > FINAL_FA_CEILING:
        raise AssertionError(
            "Fresh stable validation exceeds final FA ceiling"
        )
    if stress["false_alarms_per_1000"] > FINAL_FA_CEILING:
        raise AssertionError(
            "Fresh unstable stress exceeds final FA ceiling"
        )

    result = {
        "protocol": {
            "previous_stress_block_forbidden": [20001, 20080],
            "stable_tuning_block": [
                STABLE_TUNE_START,
                STABLE_TUNE_START + STABLE_TUNE_SEEDS - 1,
            ],
            "unstable_tuning_block": [
                UNSTABLE_TUNE_START,
                UNSTABLE_TUNE_START + UNSTABLE_TUNE_SEEDS - 1,
            ],
            "stable_validation_block": [
                VALID_START,
                VALID_START + VALID_SEEDS - 1,
            ],
            "unstable_stress_block": [
                STRESS_START,
                STRESS_START + STRESS_SEEDS - 1,
            ],
            "stage18_stage19_live_artifacts_used": False,
            "zero_false_alarm_required_on_both_tuning_regimes": True,
            "final_false_alarm_ceiling_per_1000": FINAL_FA_CEILING,
        },
        "grid_size": len(CONSERVATIVE_GRID),
        "selected_detector": selected,
        "stable_validation": validation,
        "unstable_schema_stress": stress,
    }

    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
