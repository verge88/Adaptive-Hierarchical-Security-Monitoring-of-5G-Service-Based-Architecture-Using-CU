"""Stage 19 development and synthetic validation protocol.

No Stage-18 live artifact or seed is read here.

Tuning block:     11001..11040
Validation block: 12001..12080

The synthetic scalar telemetry intentionally differs from Stage 16. It models
signed integrity accounting with clean drift, symmetric observer noise,
occasional heavy-tailed clean outliers, persistent signed attacks, and sparse
signed attacks with randomized pulse locations.

Selection rule for the multiscale detector:
1. mean false alarms <= 0.50 / 1000 clean monitoring ticks;
2. maximize the minimum recall across the four attack families;
3. maximize overall event recall;
4. minimize horizon-penalized delay;
5. minimize false alarms.

The Stage-17 directional configuration is a fixed comparator, not retuned.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
from pathlib import Path
import random
import statistics

from .stage15_detector import power_betting_mixture, upper_tail_rank
from .stage19_detector import (
    MULTISCALE_GRID,
    SPARSE_CLUSTER_GRID,
    MultiscaleDirectionalConfig,
    MultiscaleDirectionalState,
    SparseClusterDirectionalConfig,
    SparseClusterDirectionalState,
    lower_tail_rank,
)

WARMUP = 30
EPISODE_TICKS = 12
GAP_TICKS = 6
FAMILIES = (
    "persistent_positive",
    "persistent_negative",
    "sparse_positive",
    "sparse_negative",
)
REPS = 3
TOTAL_TICKS = WARMUP + len(FAMILIES) * REPS * (
    EPISODE_TICKS + GAP_TICKS
)

TUNE_START = 11001
TUNE_SEEDS = 40
VALID_START = 12001
VALID_SEEDS = 80
FALSE_ALARM_CEILING = 0.50

STAGE17_DECAY = 0.90
STAGE17_REFERENCE = 0.12
STAGE17_THRESHOLD = 5.0
STAGE17_GATE = 0.06


@dataclass(frozen=True)
class Episode:
    family: str
    start: int
    end: int
    pulse_ticks: tuple[int, ...]
    amplitude: float


class SparseSignedWorld:
    def __init__(self, seed: int):
        self.seed = seed
        rng = random.Random(seed * 19019 + 17)

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
                amplitude = rng.uniform(0.040, 0.100)
            else:
                count = rng.choice((3, 4, 5))
                local = sorted(
                    rng.sample(range(EPISODE_TICKS), count)
                )
                pulses = tuple(start + x for x in local)
                amplitude = rng.uniform(0.065, 0.155)
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

        if cursor != TOTAL_TICKS:
            raise AssertionError("Stage19 synthetic timeline mismatch")

        values = []
        for tick in range(TOTAL_TICKS):
            drift = (
                0.000010 * max(0, tick - WARMUP)
                + 0.000004 * math.sin(2 * math.pi * tick / 47)
            )
            sigma = 0.006 + 0.000015 * tick
            value = drift + rng.gauss(0.0, sigma)

            if tick >= WARMUP and rng.random() < 0.008:
                value += rng.choice((-1, 1)) * rng.uniform(
                    0.025, 0.060
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


def stage17_outputs(values: list[float]) -> list[bool]:
    calibration = values[:WARMUP]
    positive = 0.0
    negative = 0.0
    alerts = []

    for tick, value in enumerate(values):
        if tick < WARMUP:
            alerts.append(False)
            continue

        p_pos = upper_tail_rank(calibration, value)
        p_neg = lower_tail_rank(calibration, value)
        log_pos = math.log(
            max(1e-12, power_betting_mixture(p_pos))
        )
        log_neg = math.log(
            max(1e-12, power_betting_mixture(p_neg))
        )
        positive = max(
            0.0,
            STAGE17_DECAY * positive
            + log_pos
            - STAGE17_REFERENCE,
        )
        negative = max(
            0.0,
            STAGE17_DECAY * negative
            + log_neg
            - STAGE17_REFERENCE,
        )
        alert = (
            (
                positive >= STAGE17_THRESHOLD
                and p_pos <= STAGE17_GATE
            )
            or (
                negative >= STAGE17_THRESHOLD
                and p_neg <= STAGE17_GATE
            )
        )
        alerts.append(alert)
        if alert:
            positive = 0.0
            negative = 0.0
    return alerts


def multiscale_outputs(
    values: list[float],
    config: MultiscaleDirectionalConfig,
) -> list[bool]:
    state = MultiscaleDirectionalState(
        values[:WARMUP], config
    )
    alerts = []
    for tick, value in enumerate(values):
        if tick < WARMUP:
            alerts.append(False)
        else:
            alerts.append(state.observe(value)["alert"])
    return alerts


def cluster_outputs(
    values: list[float],
    config: SparseClusterDirectionalConfig,
) -> list[bool]:
    state = SparseClusterDirectionalState(
        values[:WARMUP], config
    )
    alerts = []
    for tick, value in enumerate(values):
        if tick < WARMUP:
            alerts.append(False)
        else:
            alerts.append(state.observe(value)["alert"])
    return alerts


def evaluate(world: SparseSignedWorld, alerts: list[bool]) -> dict:
    attack_ticks = {
        tick
        for episode in world.episodes
        for tick in range(episode.start, episode.end)
    }
    clean_ticks = set(range(WARMUP, TOTAL_TICKS)) - attack_ticks
    false_alarms = sum(alerts[tick] for tick in clean_ticks)

    rows = []
    for episode in world.episodes:
        inside = [
            tick
            for tick in range(episode.start, episode.end)
            if alerts[tick]
        ]
        detected = bool(inside)
        delay = (
            inside[0] - episode.start
            if detected
            else EPISODE_TICKS
        )
        rows.append(
            {
                "family": episode.family,
                "detected": detected,
                "delay": delay,
            }
        )

    per_family = {}
    for family in FAMILIES:
        selected = [
            row for row in rows if row["family"] == family
        ]
        per_family[family] = statistics.mean(
            row["detected"] for row in selected
        )

    return {
        "event_recall": statistics.mean(
            row["detected"] for row in rows
        ),
        "min_family_recall": min(per_family.values()),
        "mean_horizon_penalized_delay": statistics.mean(
            row["delay"] for row in rows
        ),
        "false_alarms_per_1000": (
            1000 * false_alarms / max(1, len(clean_ticks))
        ),
        "per_family": per_family,
    }


def summarize(rows: list[dict]) -> dict:
    per_family = {
        family: statistics.mean(
            row["per_family"][family] for row in rows
        )
        for family in FAMILIES
    }
    return {
        "event_recall": statistics.mean(
            row["event_recall"] for row in rows
        ),
        "min_family_recall": min(per_family.values()),
        "mean_horizon_penalized_delay": statistics.mean(
            row["mean_horizon_penalized_delay"]
            for row in rows
        ),
        "false_alarms_per_1000": statistics.mean(
            row["false_alarms_per_1000"]
            for row in rows
        ),
        "per_family": per_family,
    }


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
                -item["summary"]["event_recall"],
            ),
        )
    return max(
        feasible,
        key=lambda item: (
            item["summary"]["min_family_recall"],
            item["summary"]["event_recall"],
            -item["summary"][
                "mean_horizon_penalized_delay"
            ],
            -item["summary"]["false_alarms_per_1000"],
        ),
    )


def run_block(
    start_seed: int,
    n_seeds: int,
    config: MultiscaleDirectionalConfig | None,
) -> dict:
    worlds = [
        SparseSignedWorld(seed)
        for seed in range(start_seed, start_seed + n_seeds)
    ]

    stage17_rows = [
        evaluate(world, stage17_outputs(world.values))
        for world in worlds
    ]
    output = {
        "stage17_directional": summarize(stage17_rows)
    }

    if config is not None:
        multiscale_rows = [
            evaluate(
                world,
                multiscale_outputs(world.values, config),
            )
            for world in worlds
        ]
        output["multiscale_directional"] = summarize(
            multiscale_rows
        )
    return output


def tune() -> dict:
    worlds = [
        SparseSignedWorld(seed)
        for seed in range(TUNE_START, TUNE_START + TUNE_SEEDS)
    ]
    stage17_summary = summarize(
        [
            evaluate(world, stage17_outputs(world.values))
            for world in worlds
        ]
    )

    multiscale_candidates = []
    for config in MULTISCALE_GRID:
        rows = [
            evaluate(
                world,
                multiscale_outputs(world.values, config),
            )
            for world in worlds
        ]
        multiscale_candidates.append(
            {
                "family": "multiscale_log_e",
                "config": dict(config.__dict__),
                "summary": summarize(rows),
            }
        )

    cluster_candidates = []
    for config in SPARSE_CLUSTER_GRID:
        rows = [
            evaluate(
                world,
                cluster_outputs(world.values, config),
            )
            for world in worlds
        ]
        cluster_candidates.append(
            {
                "family": "bounded_tail_cluster",
                "config": dict(config.__dict__),
                "summary": summarize(rows),
            }
        )

    selected_multiscale = select_best(multiscale_candidates)
    selected_cluster = select_best(cluster_candidates)
    selected = select_best(
        [selected_multiscale, selected_cluster]
    )

    validation_worlds = [
        SparseSignedWorld(seed)
        for seed in range(VALID_START, VALID_START + VALID_SEEDS)
    ]
    validation_stage17 = summarize(
        [
            evaluate(world, stage17_outputs(world.values))
            for world in validation_worlds
        ]
    )
    if selected["family"] == "bounded_tail_cluster":
        selected_config = SparseClusterDirectionalConfig(
            **selected["config"]
        )
        validation_selected = summarize(
            [
                evaluate(
                    world,
                    cluster_outputs(world.values, selected_config),
                )
                for world in validation_worlds
            ]
        )
    else:
        selected_config = MultiscaleDirectionalConfig(
            **selected["config"]
        )
        validation_selected = summarize(
            [
                evaluate(
                    world,
                    multiscale_outputs(world.values, selected_config),
                )
                for world in validation_worlds
            ]
        )

    return {
        "protocol": {
            "tuning_block": [
                TUNE_START,
                TUNE_START + TUNE_SEEDS - 1,
            ],
            "synthetic_validation_block": [
                VALID_START,
                VALID_START + VALID_SEEDS - 1,
            ],
            "stage18_live_seeds_forbidden": [8101, 8106],
            "false_alarm_ceiling_per_1000": (
                FALSE_ALARM_CEILING
            ),
            "selection": (
                "maximize minimum family recall, then overall recall, "
                "then minimize penalized delay and false alarms"
            ),
        },
        "multiscale_log_e_grid_size": len(MULTISCALE_GRID),
        "bounded_tail_cluster_grid_size": len(SPARSE_CLUSTER_GRID),
        "stage17_tuning_block": stage17_summary,
        "selected_multiscale_log_e": selected_multiscale,
        "selected_bounded_tail_cluster": selected_cluster,
        "selected_detector": selected,
        "synthetic_validation": {
            "stage17_directional": validation_stage17,
            "selected_detector": validation_selected,
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage19_development.json",
    )
    args = parser.parse_args()
    result = tune()
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
