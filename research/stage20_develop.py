"""Stage 20 distributionally robust development selector.

Development seeds: 11001..11060 only.
Predeclared untouched final block: 12001..12200.

Selection is robust across five clean-environment modes.  Rather than accepting
only a low *mean* false-alarm rate, a candidate must keep every mode below the
declared ceiling.

The new competitive sparse and leaky channels are first reduced to Pareto
representatives at several per-mode false-alarm budgets.  Only those
representatives are combined, keeping the final combination search small and
auditable.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics

from .stage19_frozen import (
    TriPathDirectionalEvidenceEnsemble,
    frozen_page_hinkley_detector,
    frozen_single_detector,
)
from .stage20_detector import (
    COMPETITIVE_LEAKY_GRID,
    COMPETITIVE_SPARSE_GRID,
    CompetitiveLeakyDetector,
    CompetitiveSparseDetector,
)
from .stage20_simulation import (
    ALL_KINDS,
    ENVIRONMENT_MODES,
    PERSISTENT_KINDS,
    SPARSE_KINDS,
    WARMUP_TICKS,
    EnvironmentRandomizedWorld,
)

DEV_START_SEED = 11001
DEV_SEEDS = 60
FINAL_START_SEED = 12001
FINAL_SEEDS = 200

TOTAL_MEAN_FA_CEILING = 0.40
TOTAL_MODE_FA_CEILING = 0.50
PERSISTENT_RECALL_FLOOR = 0.85
PARETO_BUDGETS = (0.0, 0.18, 0.35, 0.50)


def clean_tick_set(world: EnvironmentRandomizedWorld) -> set[int]:
    windows = {
        tick
        for episode in world.episodes
        for tick in range(
            episode.start_tick,
            episode.end_tick,
        )
    }
    return (
        set(range(WARMUP_TICKS, world.total_ticks))
        - windows
    )


def detector_alarm_set(world, detector) -> set[int]:
    alerts = set()
    for tick in range(WARMUP_TICKS, world.total_ticks):
        alarm, _ = detector.observe(world.values[tick])
        if alarm:
            alerts.add(tick)
    return alerts


def event_metrics(
    world: EnvironmentRandomizedWorld,
    alerts: set[int],
) -> dict:
    clean = clean_tick_set(world)
    events = []
    for episode in world.episodes:
        inside = sorted(
            tick
            for tick in alerts
            if episode.start_tick <= tick < episode.end_tick
        )
        detected = bool(inside)
        delay = (
            inside[0] - episode.start_tick
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
    sparse = [row for row in events if row["sparse"]]
    persistent = [
        row for row in events if not row["sparse"]
    ]
    return {
        "seed": world.seed,
        "mode": world.environment.mode,
        "event_recall": statistics.mean(
            row["detected"] for row in events
        ),
        "sparse_event_recall": statistics.mean(
            row["detected"] for row in sparse
        ),
        "persistent_event_recall": statistics.mean(
            row["detected"] for row in persistent
        ),
        "horizon_penalized_delay_ticks": statistics.mean(
            row["delay"] for row in events
        ),
        "sparse_horizon_penalized_delay_ticks": statistics.mean(
            row["delay"] for row in sparse
        ),
        "false_alarms": len(alerts & clean),
        "clean_ticks": len(clean),
    }


def summarize(rows: list[dict]) -> dict:
    mean_fa = (
        1000
        * sum(row["false_alarms"] for row in rows)
        / max(1, sum(row["clean_ticks"] for row in rows))
    )
    per_mode = {}
    for mode in ENVIRONMENT_MODES:
        selected = [
            row for row in rows if row["mode"] == mode
        ]
        per_mode[mode] = {
            "event_recall": statistics.mean(
                row["event_recall"] for row in selected
            ),
            "sparse_event_recall": statistics.mean(
                row["sparse_event_recall"] for row in selected
            ),
            "persistent_event_recall": statistics.mean(
                row["persistent_event_recall"]
                for row in selected
            ),
            "false_alarms_per_1000_clean_ticks": (
                1000
                * sum(row["false_alarms"] for row in selected)
                / max(
                    1,
                    sum(row["clean_ticks"] for row in selected),
                )
            ),
        }

    return {
        "event_recall": statistics.mean(
            row["event_recall"] for row in rows
        ),
        "sparse_event_recall": statistics.mean(
            row["sparse_event_recall"] for row in rows
        ),
        "persistent_event_recall": statistics.mean(
            row["persistent_event_recall"] for row in rows
        ),
        "horizon_penalized_delay_ticks": statistics.mean(
            row["horizon_penalized_delay_ticks"]
            for row in rows
        ),
        "sparse_horizon_penalized_delay_ticks": statistics.mean(
            row["sparse_horizon_penalized_delay_ticks"]
            for row in rows
        ),
        "false_alarms_per_1000_clean_ticks": mean_fa,
        "max_mode_false_alarms_per_1000": max(
            item["false_alarms_per_1000_clean_ticks"]
            for item in per_mode.values()
        ),
        "min_mode_sparse_recall": min(
            item["sparse_event_recall"]
            for item in per_mode.values()
        ),
        "min_mode_persistent_recall": min(
            item["persistent_event_recall"]
            for item in per_mode.values()
        ),
        "per_mode": per_mode,
    }


def config_dict(config):
    output = dict(config.__dict__)
    if "windows" in output:
        output["windows"] = list(output["windows"])
    return output


def evaluate_family(worlds, grid, detector_cls):
    candidates = []
    for config in grid:
        rows = []
        for world in worlds:
            detector = detector_cls(
                world.values[:WARMUP_TICKS],
                config,
            )
            rows.append(
                event_metrics(
                    world,
                    detector_alarm_set(world, detector),
                )
            )
        candidates.append(
            {
                "config": config_dict(config),
                "object": config,
                "summary": summarize(rows),
            }
        )
    return candidates


def pareto_representatives(
    candidates,
    *,
    target: str,
):
    selected = []
    seen = set()
    for budget in PARETO_BUDGETS:
        feasible = [
            item
            for item in candidates
            if item["summary"][
                "max_mode_false_alarms_per_1000"
            ] <= budget + 1e-12
        ]
        if not feasible:
            continue
        best = max(
            feasible,
            key=lambda item: (
                item["summary"][target],
                item["summary"][
                    "min_mode_sparse_recall"
                    if target == "sparse_event_recall"
                    else "min_mode_persistent_recall"
                ],
                item["summary"]["event_recall"],
                -item["summary"][
                    "false_alarms_per_1000_clean_ticks"
                ],
            ),
        )
        key = json.dumps(
            best["config"], sort_keys=True
        )
        if key not in seen:
            selected.append(best)
            seen.add(key)
    return selected


def ensemble_rows(worlds, sparse_config, leaky_config):
    rows = []
    for world in worlds:
        calibration = world.values[:WARMUP_TICKS]
        sparse = CompetitiveSparseDetector(
            calibration, sparse_config
        )
        leaky = CompetitiveLeakyDetector(
            calibration, leaky_config
        )
        alerts = (
            detector_alarm_set(world, sparse)
            | detector_alarm_set(world, leaky)
        )
        rows.append(event_metrics(world, alerts))
    return rows


def legacy_rows(worlds, method: str):
    rows = []
    for world in worlds:
        calibration = world.values[:WARMUP_TICKS]
        if method == "stage19_tri_path":
            detector = TriPathDirectionalEvidenceEnsemble(
                calibration
            )
        elif method == "stage19_single":
            detector = frozen_single_detector(calibration)
        elif method == "stage19_page_hinkley":
            detector = frozen_page_hinkley_detector(
                calibration
            )
        else:
            raise ValueError(method)
        rows.append(
            event_metrics(
                world,
                detector_alarm_set(world, detector),
            )
        )
    return rows


def public(item):
    return {
        "config": item["config"],
        "summary": item["summary"],
    }


def develop(
    start_seed=DEV_START_SEED,
    n_seeds=DEV_SEEDS,
):
    end_seed = start_seed + n_seeds - 1
    if start_seed <= 10200 and end_seed >= 10001:
        raise ValueError(
            "Stage19 final seeds 10001..10200 are evaluation-only"
        )
    if start_seed <= 8106 and end_seed >= 8101:
        raise ValueError(
            "Stage18 live seeds 8101..8106 are evaluation-only"
        )
    if (
        start_seed <= FINAL_START_SEED + FINAL_SEEDS - 1
        and end_seed >= FINAL_START_SEED
    ):
        raise ValueError(
            "Stage20 final seeds 12001..12200 are forbidden in development"
        )

    worlds = [
        EnvironmentRandomizedWorld(seed)
        for seed in range(start_seed, start_seed + n_seeds)
    ]

    sparse_candidates = evaluate_family(
        worlds,
        COMPETITIVE_SPARSE_GRID,
        CompetitiveSparseDetector,
    )
    leaky_candidates = evaluate_family(
        worlds,
        COMPETITIVE_LEAKY_GRID,
        CompetitiveLeakyDetector,
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
        for leaky in leaky_front:
            summary = summarize(
                ensemble_rows(
                    worlds,
                    sparse["object"],
                    leaky["object"],
                )
            )
            combinations.append(
                {
                    "sparse": sparse["config"],
                    "leaky": leaky["config"],
                    "summary": summary,
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

    return {
        "protocol": {
            "development_block": [start_seed, end_seed],
            "forbidden_stage18_live": [8101, 8106],
            "forbidden_stage19_final": [10001, 10200],
            "predeclared_stage20_final": [12001, 12200],
            "environment_modes": list(ENVIRONMENT_MODES),
            "mean_fa_ceiling": TOTAL_MEAN_FA_CEILING,
            "every_mode_fa_ceiling": TOTAL_MODE_FA_CEILING,
            "persistent_recall_floor": PERSISTENT_RECALL_FLOOR,
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
            "sparse": [public(item) for item in sparse_front],
            "leaky": [public(item) for item in leaky_front],
        },
        "combination_count": len(combinations),
        "selected_competitive_ensemble": selected,
        "passes_predeclared_gate": selected is not None,
        "legacy_stage19_on_new_development": legacy,
    }


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
        default="stage20_development.json",
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
