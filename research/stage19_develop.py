"""Stage 19 development-only tuning on fresh sparse-rich worlds.

Development seeds: 9001..9040 only.
Predeclared untouched synthetic final block: 10001..10200.

Stage-18 live seeds/artifacts are forbidden development inputs.

Selection rule for every family:
1. false alarms <= 0.50 / 1000 clean ticks;
2. persistent-event recall >= 0.90;
3. maximize sparse-event recall;
4. maximize overall recall;
5. minimize horizon-penalized delay;
6. minimize false alarms.

This gives single-scale directional and Page-Hinkley strong development-tuned
comparators rather than comparing only against old frozen thresholds.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import statistics

from .stage15_detector import (
    power_betting_mixture,
    upper_tail_rank,
)
from .stage19_detector import (
    MULTISCALE_GRID,
    PAGE_HINKLEY_GRID,
    SINGLE_SCALE_GRID,
    MultiScaleDirectionalConfig,
    ScalarPageHinkleyConfig,
    SingleScaleDirectionalConfig,
    log_mean_exp,
    lower_tail_rank,
)
from .stage19_simulation import (
    PERSISTENT_KINDS,
    SPARSE_KINDS,
    WARMUP_TICKS,
    SparseIntegrityWorld,
)

DEV_START_SEED = 9001
DEV_SEEDS = 40
FINAL_START_SEED = 10001
FINAL_SEEDS = 200
FALSE_ALARM_CEILING = 0.50
PERSISTENT_RECALL_FLOOR = 0.90


def build_trace(world: SparseIntegrityWorld) -> dict:
    calibration = world.values[:WARMUP_TICKS]
    abs_calibration = [abs(value) for value in calibration]
    trace = []

    for tick, value in enumerate(world.values):
        if tick < WARMUP_TICKS:
            continue
        p_positive = upper_tail_rank(calibration, value)
        p_negative = lower_tail_rank(calibration, value)
        p_absolute = upper_tail_rank(
            abs_calibration, abs(value)
        )
        trace.append(
            (
                tick,
                p_positive,
                p_negative,
                p_absolute,
                math.log(
                    max(
                        1e-12,
                        power_betting_mixture(p_positive),
                    )
                ),
                math.log(
                    max(
                        1e-12,
                        power_betting_mixture(p_negative),
                    )
                ),
                -math.log(max(1e-12, p_absolute)),
            )
        )
    return {
        "calibration": calibration,
        "trace": trace,
    }


def event_metrics(
    world: SparseIntegrityWorld,
    alert_ticks: set[int],
    false_alarms: int,
    clean_ticks: int,
) -> dict:
    events = []
    for episode in world.episodes:
        alarms = sorted(
            tick
            for tick in alert_ticks
            if episode.start_tick
            <= tick
            < episode.end_tick
        )
        detected = bool(alarms)
        delay = (
            alarms[0] - episode.start_tick
            if detected
            else episode.end_tick - episode.start_tick
        )
        events.append(
            {
                "kind": episode.kind,
                "sparse": episode.sparse,
                "detected": detected,
                "delay": delay,
            }
        )

    sparse = [event for event in events if event["sparse"]]
    persistent = [
        event for event in events if not event["sparse"]
    ]
    return {
        "event_recall": statistics.mean(
            event["detected"] for event in events
        ),
        "sparse_event_recall": statistics.mean(
            event["detected"] for event in sparse
        ),
        "persistent_event_recall": statistics.mean(
            event["detected"] for event in persistent
        ),
        "horizon_penalized_delay_ticks": statistics.mean(
            event["delay"] for event in events
        ),
        "sparse_horizon_penalized_delay_ticks": statistics.mean(
            event["delay"] for event in sparse
        ),
        "false_alarms_per_1000_clean_ticks": (
            1000 * false_alarms / max(1, clean_ticks)
        ),
    }


def clean_tick_set(world: SparseIntegrityWorld) -> set[int]:
    attack_windows = {
        tick
        for episode in world.episodes
        for tick in range(
            episode.start_tick, episode.end_tick
        )
    }
    return (
        set(range(WARMUP_TICKS, world.total_ticks))
        - attack_windows
    )


def evaluate_multiscale(world, prepared, config):
    positive = [0.0] * len(config.decays)
    negative = [0.0] * len(config.decays)
    alerts = set()
    clean = clean_tick_set(world)
    false = 0

    for (
        tick,
        p_positive,
        p_negative,
        _,
        log_positive,
        log_negative,
        _,
    ) in prepared["trace"]:
        for index, decay in enumerate(config.decays):
            positive[index] = max(
                0.0,
                decay * positive[index]
                + log_positive
                - config.reference,
            )
            negative[index] = max(
                0.0,
                decay * negative[index]
                + log_negative
                - config.reference,
            )

        positive_score = log_mean_exp(positive)
        negative_score = log_mean_exp(negative)
        alarm = (
            (
                positive_score >= config.threshold
                and p_positive <= config.direction_gate_p
            )
            or (
                negative_score >= config.threshold
                and p_negative <= config.direction_gate_p
            )
        )
        if alarm:
            alerts.add(tick)
            false += int(tick in clean)
            positive = [0.0] * len(config.decays)
            negative = [0.0] * len(config.decays)

    return event_metrics(
        world, alerts, false, len(clean)
    )


def evaluate_single(world, prepared, config):
    positive = 0.0
    negative = 0.0
    alerts = set()
    clean = clean_tick_set(world)
    false = 0

    for (
        tick,
        p_positive,
        p_negative,
        _,
        log_positive,
        log_negative,
        _,
    ) in prepared["trace"]:
        positive = max(
            0.0,
            config.decay * positive
            + log_positive
            - config.reference,
        )
        negative = max(
            0.0,
            config.decay * negative
            + log_negative
            - config.reference,
        )
        alarm = (
            (
                positive >= config.threshold
                and p_positive <= config.direction_gate_p
            )
            or (
                negative >= config.threshold
                and p_negative <= config.direction_gate_p
            )
        )
        if alarm:
            alerts.add(tick)
            false += int(tick in clean)
            positive = 0.0
            negative = 0.0

    return event_metrics(
        world, alerts, false, len(clean)
    )


def evaluate_page_hinkley(world, prepared, config):
    mean = 1.0
    cumulative = 0.0
    minimum = 0.0
    alerts = set()
    clean = clean_tick_set(world)
    false = 0

    for tick, _, _, p_absolute, _, _, surprise in prepared[
        "trace"
    ]:
        mean = (
            (1.0 - config.mean_alpha) * mean
            + config.mean_alpha * surprise
        )
        cumulative += surprise - mean - config.delta
        minimum = min(minimum, cumulative)
        statistic = cumulative - minimum
        alarm = (
            statistic >= config.threshold
            and p_absolute <= config.gate_p
        )
        if alarm:
            alerts.add(tick)
            false += int(tick in clean)
            cumulative = 0.0
            minimum = 0.0

    return event_metrics(
        world, alerts, false, len(clean)
    )


def summarize(rows):
    return {
        key: statistics.mean(row[key] for row in rows)
        for key in (
            "event_recall",
            "sparse_event_recall",
            "persistent_event_recall",
            "horizon_penalized_delay_ticks",
            "sparse_horizon_penalized_delay_ticks",
            "false_alarms_per_1000_clean_ticks",
        )
    }


def select_best(candidates):
    fa_ok = [
        item
        for item in candidates
        if item["summary"][
            "false_alarms_per_1000_clean_ticks"
        ] <= FALSE_ALARM_CEILING
    ]
    strong = [
        item
        for item in fa_ok
        if item["summary"]["persistent_event_recall"]
        >= PERSISTENT_RECALL_FLOOR
    ]
    pool = strong or fa_ok or candidates

    if strong or fa_ok:
        return max(
            pool,
            key=lambda item: (
                item["summary"]["sparse_event_recall"],
                item["summary"]["persistent_event_recall"],
                item["summary"]["event_recall"],
                -item["summary"][
                    "horizon_penalized_delay_ticks"
                ],
                -item["summary"][
                    "false_alarms_per_1000_clean_ticks"
                ],
            ),
        )

    return min(
        pool,
        key=lambda item: (
            item["summary"][
                "false_alarms_per_1000_clean_ticks"
            ],
            -item["summary"]["sparse_event_recall"],
            -item["summary"]["persistent_event_recall"],
        ),
    )


def config_dict(config):
    result = dict(config.__dict__)
    if "decays" in result:
        result["decays"] = list(result["decays"])
    return result


def develop(
    start_seed=DEV_START_SEED,
    n_seeds=DEV_SEEDS,
):
    end_seed = start_seed + n_seeds - 1
    if start_seed <= 8106 and end_seed >= 8101:
        raise ValueError(
            "Stage18 live seeds 8101..8106 are evaluation-only"
        )
    if (
        start_seed <= FINAL_START_SEED + FINAL_SEEDS - 1
        and end_seed >= FINAL_START_SEED
    ):
        raise ValueError(
            "Stage19 final seeds 10001..10200 are forbidden in development"
        )

    worlds = [
        SparseIntegrityWorld(seed)
        for seed in range(start_seed, start_seed + n_seeds)
    ]
    prepared = [build_trace(world) for world in worlds]

    families = {
        "multiscale_directional": (
            MULTISCALE_GRID,
            evaluate_multiscale,
        ),
        "single_scale_directional": (
            SINGLE_SCALE_GRID,
            evaluate_single,
        ),
        "page_hinkley": (
            PAGE_HINKLEY_GRID,
            evaluate_page_hinkley,
        ),
    }

    output = {
        "protocol": {
            "development_block": [
                start_seed,
                end_seed,
            ],
            "forbidden_stage18_live_seeds": [8101, 8106],
            "predeclared_synthetic_final": [10001, 10200],
            "false_alarm_ceiling_per_1000": (
                FALSE_ALARM_CEILING
            ),
            "persistent_recall_floor": (
                PERSISTENT_RECALL_FLOOR
            ),
            "selection": (
                "maximize sparse recall under FA ceiling and persistent "
                "recall floor; then persistent/overall recall and delay"
            ),
        },
        "families": {},
        "selected": {},
    }

    for name, (grid, evaluator) in families.items():
        candidates = []
        for config in grid:
            rows = [
                evaluator(world, trace, config)
                for world, trace in zip(worlds, prepared)
            ]
            candidates.append(
                {
                    "config": config_dict(config),
                    "summary": summarize(rows),
                }
            )
        output["families"][name] = {
            "grid_size": len(grid),
        }
        output["selected"][name] = select_best(
            candidates
        )

    multi = output["selected"]["multiscale_directional"]
    single = output["selected"]["single_scale_directional"]
    output["development_effect_multiscale_minus_single"] = {
        key: multi["summary"][key] - single["summary"][key]
        for key in multi["summary"]
    }
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start-seed",
        type=int,
        default=DEV_START_SEED,
    )
    parser.add_argument(
        "--seeds",
        type=int,
        default=DEV_SEEDS,
    )
    parser.add_argument(
        "--output",
        default="stage19_development.json",
    )
    args = parser.parse_args()

    result = develop(args.start_seed, args.seeds)
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
