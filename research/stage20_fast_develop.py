"""Exact feature-trace replay for Stage-20 development.

This accelerates research.stage20_develop without changing its grids or
selection rule.  Adaptive robust z/p/e features depend only on the world and
(center_alpha, scale_alpha), so each pair is computed once per world and then
replayed through every sequential recurrence.

Before selection, representative fast recurrences are checked against the full
detector classes on the same world.
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
from .stage17_detector import lower_tail_rank
from .stage20_develop import (
    DEV_SEEDS,
    DEV_START_SEED,
    PARETO_BUDGETS,
    PERSISTENT_RECALL_FLOOR,
    TOTAL_MEAN_FA_CEILING,
    TOTAL_MODE_FA_CEILING,
    clean_tick_set,
    event_metrics,
    legacy_rows,
    pareto_representatives,
    summarize,
)
from .stage20_detector import (
    COMPETITIVE_LEAKY_GRID,
    COMPETITIVE_SPARSE_GRID,
    CompetitiveLeakyDetector,
    CompetitiveSparseDetector,
    robust_center_scale,
)
from .stage20_simulation import (
    WARMUP_TICKS,
    EnvironmentRandomizedWorld,
)

ADAPTATION_PAIRS = (
    (0.03, 0.02),
    (0.07, 0.04),
)


def build_trace(
    world: EnvironmentRandomizedWorld,
    center_alpha: float,
    scale_alpha: float,
) -> list[tuple]:
    calibration = world.values[:WARMUP_TICKS]
    center, scale = robust_center_scale(calibration)
    initial_scale = scale
    calibration_z = [
        (value - center) / scale
        for value in calibration
    ]
    trace = []

    for tick in range(WARMUP_TICKS, world.total_ticks):
        value = world.values[tick]
        residual = value - center
        z = residual / max(1e-12, scale)
        p_positive = upper_tail_rank(
            calibration_z, z
        )
        p_negative = lower_tail_rank(
            calibration_z, z
        )
        log_positive = max(
            0.0,
            math.log(
                max(
                    1e-12,
                    power_betting_mixture(p_positive),
                )
            ),
        )
        log_negative = max(
            0.0,
            math.log(
                max(
                    1e-12,
                    power_betting_mixture(p_negative),
                )
            ),
        )
        trace.append(
            (
                tick,
                z,
                p_positive,
                p_negative,
                log_positive,
                log_negative,
            )
        )

        cap = 3.0 * scale
        clipped = max(-cap, min(cap, residual))
        center += center_alpha * clipped
        target = 1.2533141373 * abs(clipped)
        floor = 0.45 * initial_scale
        ceiling = 4.0 * initial_scale
        target = max(floor, min(ceiling, target))
        scale = (
            (1.0 - scale_alpha) * scale
            + scale_alpha * target
        )
        scale = max(floor, min(ceiling, scale))

    return trace


def sparse_alerts(trace, config) -> set[int]:
    positive = []
    negative = []
    alerts = set()

    for (
        tick,
        z,
        p_positive,
        p_negative,
        log_positive,
        log_negative,
    ) in trace:
        outer_floor = tick - max(config.windows) + 1
        positive = [
            item for item in positive
            if item[0] >= outer_floor
        ]
        negative = [
            item for item in negative
            if item[0] >= outer_floor
        ]

        positive_hit = (
            z >= config.magnitude_gate_z
            and p_positive <= config.tail_gate_p
        )
        negative_hit = (
            z <= -config.magnitude_gate_z
            and p_negative <= config.tail_gate_p
        )
        if positive_hit:
            positive.append((tick, log_positive))
        if negative_hit:
            negative.append((tick, log_negative))

        positive_alarm = False
        negative_alarm = False
        for window in config.windows:
            floor = tick - window + 1
            pos = [
                evidence
                for hit_tick, evidence in positive
                if hit_tick >= floor
            ]
            neg = [
                evidence
                for hit_tick, evidence in negative
                if hit_tick >= floor
            ]
            pos_score = (
                sum(pos)
                - config.opposition_penalty * sum(neg)
            )
            neg_score = (
                sum(neg)
                - config.opposition_penalty * sum(pos)
            )
            positive_alarm = positive_alarm or (
                positive_hit
                and len(pos) >= config.min_hits
                and pos_score >= config.score_threshold
            )
            negative_alarm = negative_alarm or (
                negative_hit
                and len(neg) >= config.min_hits
                and neg_score >= config.score_threshold
            )
        if positive_alarm or negative_alarm:
            alerts.add(tick)
            positive = []
            negative = []

    return alerts


def leaky_alerts(trace, config) -> set[int]:
    positive = 0.0
    negative = 0.0
    alerts = set()

    for (
        tick,
        _,
        p_positive,
        p_negative,
        log_positive,
        log_negative,
    ) in trace:
        previous_positive = positive
        previous_negative = negative
        positive = max(
            0.0,
            config.decay * previous_positive
            + log_positive
            - config.reference
            - config.opposition_penalty * log_negative,
        )
        negative = max(
            0.0,
            config.decay * previous_negative
            + log_negative
            - config.reference
            - config.opposition_penalty * log_positive,
        )
        alarm = (
            (
                positive >= config.threshold
                and p_positive <= config.tail_gate_p
            )
            or (
                negative >= config.threshold
                and p_negative <= config.tail_gate_p
            )
        )
        if alarm:
            alerts.add(tick)
            positive = 0.0
            negative = 0.0

    return alerts


def full_alerts(world, detector) -> set[int]:
    alerts = set()
    for tick in range(WARMUP_TICKS, world.total_ticks):
        alarm, _ = detector.observe(world.values[tick])
        if alarm:
            alerts.add(tick)
    return alerts


def verify_exact_replay(world, traces):
    sparse_config = COMPETITIVE_SPARSE_GRID[
        len(COMPETITIVE_SPARSE_GRID) // 3
    ]
    leaky_config = COMPETITIVE_LEAKY_GRID[
        len(COMPETITIVE_LEAKY_GRID) // 3
    ]
    calibration = world.values[:WARMUP_TICKS]

    sparse_pair = (
        sparse_config.center_alpha,
        sparse_config.scale_alpha,
    )
    leaky_pair = (
        leaky_config.center_alpha,
        leaky_config.scale_alpha,
    )
    if sparse_alerts(
        traces[sparse_pair], sparse_config
    ) != full_alerts(
        world,
        CompetitiveSparseDetector(
            calibration, sparse_config
        ),
    ):
        raise AssertionError(
            "Fast sparse replay differs from full detector"
        )
    if leaky_alerts(
        traces[leaky_pair], leaky_config
    ) != full_alerts(
        world,
        CompetitiveLeakyDetector(
            calibration, leaky_config
        ),
    ):
        raise AssertionError(
            "Fast leaky replay differs from full detector"
        )


def family_candidates(
    worlds,
    traces_by_seed,
    grid,
    alarm_fn,
):
    candidates = []
    for config in grid:
        pair = (
            config.center_alpha,
            config.scale_alpha,
        )
        rows = []
        for world in worlds:
            alerts = alarm_fn(
                traces_by_seed[world.seed][pair],
                config,
            )
            rows.append(event_metrics(world, alerts))
        data = dict(config.__dict__)
        if "windows" in data:
            data["windows"] = list(data["windows"])
        candidates.append(
            {
                "config": data,
                "object": config,
                "summary": summarize(rows),
            }
        )
    return candidates


def develop_fast():
    worlds = [
        EnvironmentRandomizedWorld(seed)
        for seed in range(
            DEV_START_SEED,
            DEV_START_SEED + DEV_SEEDS,
        )
    ]
    traces_by_seed = {
        world.seed: {
            pair: build_trace(world, *pair)
            for pair in ADAPTATION_PAIRS
        }
        for world in worlds
    }
    verify_exact_replay(
        worlds[0],
        traces_by_seed[worlds[0].seed],
    )

    sparse_candidates = family_candidates(
        worlds,
        traces_by_seed,
        COMPETITIVE_SPARSE_GRID,
        sparse_alerts,
    )
    leaky_candidates = family_candidates(
        worlds,
        traces_by_seed,
        COMPETITIVE_LEAKY_GRID,
        leaky_alerts,
    )
    sparse_front = pareto_representatives(
        sparse_candidates,
        target="sparse_event_recall",
    )
    leaky_front = pareto_representatives(
        leaky_candidates,
        target="persistent_event_recall",
    )

    combinations = []
    for sparse in sparse_front:
        sparse_pair = (
            sparse["object"].center_alpha,
            sparse["object"].scale_alpha,
        )
        for leaky in leaky_front:
            leaky_pair = (
                leaky["object"].center_alpha,
                leaky["object"].scale_alpha,
            )
            rows = []
            for world in worlds:
                alerts = (
                    sparse_alerts(
                        traces_by_seed[world.seed][sparse_pair],
                        sparse["object"],
                    )
                    | leaky_alerts(
                        traces_by_seed[world.seed][leaky_pair],
                        leaky["object"],
                    )
                )
                rows.append(event_metrics(world, alerts))
            combinations.append(
                {
                    "sparse": sparse["config"],
                    "leaky": leaky["config"],
                    "summary": summarize(rows),
                }
            )

    feasible = [
        item
        for item in combinations
        if item["summary"][
            "false_alarms_per_1000_clean_ticks"
        ] <= TOTAL_MEAN_FA_CEILING
        and item["summary"][
            "max_mode_false_alarms_per_1000"
        ] <= TOTAL_MODE_FA_CEILING
        and item["summary"]["persistent_event_recall"]
        >= PERSISTENT_RECALL_FLOOR
    ]
    selected = (
        max(
            feasible,
            key=lambda item: (
                item["summary"]["min_mode_sparse_recall"],
                item["summary"]["sparse_event_recall"],
                item["summary"]["persistent_event_recall"],
                item["summary"]["event_recall"],
                -item["summary"][
                    "horizon_penalized_delay_ticks"
                ],
            ),
        )
        if feasible
        else None
    )

    legacy = {
        name: summarize(legacy_rows(worlds, name))
        for name in (
            "stage19_tri_path",
            "stage19_single",
            "stage19_page_hinkley",
        )
    }

    def public(item):
        return {
            "config": item["config"],
            "summary": item["summary"],
        }

    return {
        "protocol": {
            "development_block": [11001, 11060],
            "predeclared_final": [12001, 12200],
            "exact_trace_replay_verified": True,
            "grid_unchanged": True,
            "mean_fa_ceiling": TOTAL_MEAN_FA_CEILING,
            "every_mode_fa_ceiling": TOTAL_MODE_FA_CEILING,
            "persistent_recall_floor": PERSISTENT_RECALL_FLOOR,
            "pareto_budgets": list(PARETO_BUDGETS),
        },
        "grid_sizes": {
            "competitive_sparse": len(
                COMPETITIVE_SPARSE_GRID
            ),
            "competitive_leaky": len(
                COMPETITIVE_LEAKY_GRID
            ),
        },
        "pareto_fronts": {
            "sparse": [public(x) for x in sparse_front],
            "leaky": [public(x) for x in leaky_front],
        },
        "combination_count": len(combinations),
        "selected_competitive_ensemble": selected,
        "passes_predeclared_gate": selected is not None,
        "legacy_stage19_on_new_development": legacy,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage20_fast_development.json",
    )
    args = parser.parse_args()
    result = develop_fast()
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
