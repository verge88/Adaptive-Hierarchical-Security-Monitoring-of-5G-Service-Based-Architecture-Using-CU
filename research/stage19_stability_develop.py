"""Stage 19 stability-gated sparse detector development.

No Stage-18 live artifacts are read.

Live-like discrete accounting tuning:     13001..13040
Live-like discrete accounting validation: 14001..14080
Continuous-noise stress validation:       12001..12080

The selected detector must:
- stay <= 0.50 false alarms / 1000 clean ticks on live-like tuning;
- maximize minimum recall over persistent/sparse positive/negative attacks;
- preserve the Stage-17 behavior on the continuous-noise stress regime by
  disabling the sparse quorum when calibration is not structurally stable.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import random
import statistics

from .stage19_develop import (
    EPISODE_TICKS,
    FAMILIES,
    GAP_TICKS,
    REPS,
    TOTAL_TICKS,
    WARMUP,
    SparseSignedWorld,
    evaluate,
    stage17_outputs,
    summarize,
)
from .stage19_detector import (
    STABILITY_GATED_GRID,
    StabilityGatedQuorumConfig,
    StabilityGatedQuorumState,
)

TUNE_START = 13001
TUNE_SEEDS = 40
VALID_START = 14001
VALID_SEEDS = 80
STRESS_START = 12001
STRESS_SEEDS = 80
FALSE_ALARM_CEILING = 0.50


@dataclass(frozen=True)
class Episode:
    family: str
    start: int
    end: int
    pulse_ticks: tuple[int, ...]
    amplitude: float


class DiscreteAccountingWorld:
    """Live-like paired canonical-accounting signal.

    Clean observations are usually exactly zero, with occasional tiny benign
    serialization jitter and very rare larger reconciliation mismatches.
    """

    def __init__(self, seed: int):
        self.seed = seed
        rng = random.Random(seed * 19191 + 29)

        kinds = [
            family
            for family in FAMILIES
            for _ in range(REPS)
        ]
        rng.shuffle(kinds)

        self.episodes: list[Episode] = []
        cursor = WARMUP
        for family in kinds:
            start = cursor
            end = start + EPISODE_TICKS
            if family.startswith("persistent"):
                pulses = tuple(range(start, end))
                amplitude = rng.uniform(0.030, 0.090)
            else:
                count = rng.choice((3, 4, 5))
                local = sorted(
                    rng.sample(range(EPISODE_TICKS), count)
                )
                pulses = tuple(start + x for x in local)
                amplitude = rng.uniform(0.025, 0.075)
            self.episodes.append(
                Episode(
                    family=family,
                    start=start,
                    end=end,
                    pulse_ticks=pulses,
                    amplitude=amplitude,
                )
            )
            cursor = end + GAP_TICKS

        values = []
        for tick in range(TOTAL_TICKS):
            draw = rng.random()
            if draw < 0.965:
                value = 0.0
            elif draw < 0.995:
                value = rng.choice((-1, 1)) * rng.uniform(
                    0.0005, 0.004
                )
            else:
                value = rng.choice((-1, 1)) * rng.uniform(
                    0.008, 0.018
                )

            episode = self.episode_for_tick(tick)
            if episode is not None and tick in episode.pulse_ticks:
                sign = (
                    1.0
                    if episode.family.endswith("positive")
                    else -1.0
                )
                value += sign * episode.amplitude

            values.append(value)

        self.values = values

    def episode_for_tick(self, tick: int):
        for episode in self.episodes:
            if episode.start <= tick < episode.end:
                return episode
        return None


def stability_outputs(
    values: list[float],
    config: StabilityGatedQuorumConfig,
) -> tuple[list[bool], bool, float]:
    state = StabilityGatedQuorumState(
        values[:WARMUP], config
    )
    alerts = []
    for tick, value in enumerate(values):
        if tick < WARMUP:
            alerts.append(False)
        else:
            alerts.append(state.observe(value)["alert"])
    return (
        alerts,
        state.quorum_enabled,
        state.stable_fraction,
    )


def select_best(candidates: list[dict]) -> dict:
    feasible = [
        item
        for item in candidates
        if item["summary"]["false_alarms_per_1000"]
        <= FALSE_ALARM_CEILING
    ]
    if not feasible:
        return min(
            candidates,
            key=lambda item: (
                item["summary"]["false_alarms_per_1000"],
                -item["summary"]["min_family_recall"],
            ),
        )
    return max(
        feasible,
        key=lambda item: (
            item["summary"]["min_family_recall"],
            item["summary"]["event_recall"],
            -item["summary"]["mean_horizon_penalized_delay"],
            -item["summary"]["false_alarms_per_1000"],
        ),
    )


def evaluate_block(worlds, config):
    rows = []
    enabled = []
    stable = []
    for world in worlds:
        alerts, is_enabled, stable_fraction = stability_outputs(
            world.values, config
        )
        rows.append(evaluate(world, alerts))
        enabled.append(is_enabled)
        stable.append(stable_fraction)
    result = summarize(rows)
    result["quorum_enabled_fraction"] = statistics.mean(enabled)
    result["mean_warmup_stable_fraction"] = statistics.mean(stable)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage19_stability_development.json",
    )
    args = parser.parse_args()

    tune_worlds = [
        DiscreteAccountingWorld(seed)
        for seed in range(TUNE_START, TUNE_START + TUNE_SEEDS)
    ]

    stage17_tune = summarize(
        [
            evaluate(world, stage17_outputs(world.values))
            for world in tune_worlds
        ]
    )

    candidates = []
    for config in STABILITY_GATED_GRID:
        summary = evaluate_block(tune_worlds, config)
        candidates.append(
            {
                "config": dict(config.__dict__),
                "summary": summary,
            }
        )
    selected = select_best(candidates)
    selected_config = StabilityGatedQuorumConfig(
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
        validation_worlds, selected_config
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
        stress_worlds, selected_config
    )

    if (
        stress_selected["false_alarms_per_1000"]
        > FALSE_ALARM_CEILING
    ):
        raise AssertionError(
            "Stability-gated detector violates stress false-alarm ceiling"
        )

    result = {
        "protocol": {
            "live_like_tuning_block": [
                TUNE_START,
                TUNE_START + TUNE_SEEDS - 1,
            ],
            "live_like_validation_block": [
                VALID_START,
                VALID_START + VALID_SEEDS - 1,
            ],
            "continuous_noise_stress_block": [
                STRESS_START,
                STRESS_START + STRESS_SEEDS - 1,
            ],
            "stage18_live_artifacts_used": False,
            "stage18_live_seeds_forbidden": [8101, 8106],
            "false_alarm_ceiling_per_1000": (
                FALSE_ALARM_CEILING
            ),
        },
        "grid_size": len(STABILITY_GATED_GRID),
        "stage17_live_like_tuning": stage17_tune,
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
