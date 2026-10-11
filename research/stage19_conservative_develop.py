"""Stage 19 conservative stability-gated development.

Previous live-like validation blocks are now inspected and are not reused for
selection.

Fresh blocks:
- tuning:                 15001..15060
- live-like validation:   16001..16120
- continuous-noise stress:17001..17080

Selection requires ZERO false alarms on the complete tuning block before recall
or delay are considered. This is deliberately stricter than the final target
of <= 0.50 / 1000 clean ticks.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage19_develop import (
    SparseSignedWorld,
    evaluate,
    stage17_outputs,
    summarize,
)
from .stage19_detector import (
    STABILITY_GATED_GRID,
    StabilityGatedQuorumConfig,
)
from .stage19_stability_develop import (
    DiscreteAccountingWorld,
    evaluate_block,
)

TUNE_START = 15001
TUNE_SEEDS = 60
VALID_START = 16001
VALID_SEEDS = 120
STRESS_START = 17001
STRESS_SEEDS = 80
FINAL_FA_CEILING = 0.50


def select_zero_fa(candidates: list[dict]) -> dict:
    zero_fa = [
        item
        for item in candidates
        if item["summary"]["false_alarms_per_1000"] == 0.0
    ]
    if not zero_fa:
        raise AssertionError(
            "No Stage19 configuration achieved zero tuning false alarms"
        )
    return max(
        zero_fa,
        key=lambda item: (
            item["summary"]["min_family_recall"],
            item["summary"]["event_recall"],
            -item["summary"]["mean_horizon_penalized_delay"],
        ),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage19_conservative_development.json",
    )
    args = parser.parse_args()

    tuning_worlds = [
        DiscreteAccountingWorld(seed)
        for seed in range(TUNE_START, TUNE_START + TUNE_SEEDS)
    ]
    candidates = []
    for config in STABILITY_GATED_GRID:
        summary = evaluate_block(tuning_worlds, config)
        candidates.append(
            {
                "config": dict(config.__dict__),
                "summary": summary,
            }
        )
    selected = select_zero_fa(candidates)
    config = StabilityGatedQuorumConfig(
        **selected["config"]
    )

    validation_worlds = [
        DiscreteAccountingWorld(seed)
        for seed in range(
            VALID_START, VALID_START + VALID_SEEDS
        )
    ]
    validation_stage17 = summarize(
        [
            evaluate(world, stage17_outputs(world.values))
            for world in validation_worlds
        ]
    )
    validation_selected = evaluate_block(
        validation_worlds, config
    )

    stress_worlds = [
        SparseSignedWorld(seed)
        for seed in range(
            STRESS_START, STRESS_START + STRESS_SEEDS
        )
    ]
    stress_stage17 = summarize(
        [
            evaluate(world, stage17_outputs(world.values))
            for world in stress_worlds
        ]
    )
    stress_selected = evaluate_block(
        stress_worlds, config
    )

    if (
        validation_selected["false_alarms_per_1000"]
        > FINAL_FA_CEILING
    ):
        raise AssertionError(
            "Fresh live-like validation exceeds final FA ceiling"
        )
    if (
        stress_selected["false_alarms_per_1000"]
        > FINAL_FA_CEILING
    ):
        raise AssertionError(
            "Fresh continuous-noise stress exceeds final FA ceiling"
        )

    result = {
        "protocol": {
            "fresh_tuning_block": [
                TUNE_START,
                TUNE_START + TUNE_SEEDS - 1,
            ],
            "fresh_live_like_validation_block": [
                VALID_START,
                VALID_START + VALID_SEEDS - 1,
            ],
            "fresh_continuous_stress_block": [
                STRESS_START,
                STRESS_START + STRESS_SEEDS - 1,
            ],
            "tuning_false_alarm_requirement": 0.0,
            "final_false_alarm_ceiling_per_1000": (
                FINAL_FA_CEILING
            ),
            "stage18_live_artifacts_used": False,
        },
        "selected_detector": selected,
        "live_like_validation": {
            "stage17_directional": validation_stage17,
            "stability_gated_quorum": validation_selected,
        },
        "continuous_noise_stress_validation": {
            "stage17_directional": stress_stage17,
            "stability_gated_quorum": stress_selected,
        },
    }

    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
