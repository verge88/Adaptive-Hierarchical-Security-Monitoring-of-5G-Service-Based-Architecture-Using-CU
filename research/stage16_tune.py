"""Reproducible tuning of strong Stage-16 comparison detectors.

Only classic baselines are tuned here. The hierarchical e-CUSUM imported from
Stage 15 remains completely frozen.

Selection rule:
1. use tuning seeds 4001..4024 only;
2. retain configurations with mean false alarms <= 0.50 / 1000 clean checks;
3. among feasible configurations maximize primary event recall;
4. break ties by lower horizon-penalized delay, then lower false alarms.
If no configuration satisfies the false-alarm ceiling, choose the lowest
false-alarm configuration and break ties by recall/delay.

For speed, detector-independent calibrated surprise traces are computed once
per tuning world and then replayed through every recurrence/configuration. This
is mathematically identical to re-running CalibratedSurprise for every grid
point because the shared feature transform has no configuration parameters.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics

from .stage15_simulation import N_NF, STEP_SECONDS, WARMUP
from .stage16_detectors import (
    CUSUM_GRID,
    EWMA_GRID,
    PAGE_HINKLEY_GRID,
    STATIC_GRID,
    CalibratedSurprise,
    config_to_dict,
)
from .stage16_simulation import WorldOOD, fixed_schedule

TUNE_START_SEED = 4001
TUNE_SEEDS = 24
FALSE_ALARM_CEILING = 0.50

FAMILIES = {
    "calibrated_static": STATIC_GRID,
    "ewma": EWMA_GRID,
    "cusum": CUSUM_GRID,
    "page_hinkley": PAGE_HINKLEY_GRID,
}


def build_trace(world):
    feature = CalibratedSurprise(world)
    checks = []
    for tick, row in enumerate(world.samples):
        t = tick * STEP_SECONDS
        if t < WARMUP:
            continue
        hierarchical = feature.risk.risks(row)
        for nf in fixed_schedule(tick):
            score, p_integrity, _ = feature.evidence_features(
                nf, row[nf], hierarchical[nf]
            )
            checks.append((nf, t, score, p_integrity))
    return checks


def _alarm_state(name, config):
    if name in ("ewma", "cusum"):
        return {"state": [0.0] * N_NF}
    if name == "page_hinkley":
        return {
            "mean": [1.0] * N_NF,
            "cumulative": [0.0] * N_NF,
            "minimum": [0.0] * N_NF,
        }
    return {}


def _candidate_alarm(name, config, state, nf, score, p_integrity):
    gate = p_integrity <= config.integrity_gate_p

    if name == "calibrated_static":
        return score >= config.threshold and gate

    if name == "ewma":
        values = state["state"]
        values[nf] = (
            (1.0 - config.alpha) * values[nf]
            + config.alpha * score
        )
        alarm = values[nf] >= config.threshold and gate
        if alarm:
            values[nf] = 0.0
        return alarm

    if name == "cusum":
        values = state["state"]
        values[nf] = max(
            0.0,
            values[nf] + score - config.reference,
        )
        alarm = values[nf] >= config.threshold and gate
        if alarm:
            values[nf] = 0.0
        return alarm

    if name == "page_hinkley":
        means = state["mean"]
        cumulative = state["cumulative"]
        minimum = state["minimum"]
        means[nf] = (
            (1.0 - config.mean_alpha) * means[nf]
            + config.mean_alpha * score
        )
        cumulative[nf] += score - means[nf] - config.delta
        minimum[nf] = min(minimum[nf], cumulative[nf])
        statistic = cumulative[nf] - minimum[nf]
        alarm = statistic >= config.threshold and gate
        if alarm:
            cumulative[nf] = 0.0
            minimum[nf] = 0.0
        return alarm

    raise ValueError(name)


def evaluate_trace(world, checks, name, config):
    state = _alarm_state(name, config)
    found = {attack.nf: None for attack in world.attacks}
    false_alarms = 0
    clean_checks = 0

    for nf, t, score, p_integrity in checks:
        alert = _candidate_alarm(
            name, config, state, nf, score, p_integrity
        )
        if world.active_attack(nf, t):
            if alert and found[nf] is None:
                found[nf] = t
        else:
            clean_checks += 1
            false_alarms += int(alert)

    def event_metrics(attacks):
        detected = 0
        delays = []
        normalized = []
        for attack in attacks:
            duration = attack.end - attack.start
            alarm = found[attack.nf]
            if alarm is None:
                delay = duration
            else:
                detected += 1
                delay = max(0, alarm - attack.start)
            delays.append(delay)
            normalized.append(delay / max(1, duration))
        return {
            "event_recall": detected / max(1, len(attacks)),
            "delay": statistics.mean(delays),
            "normalized": statistics.mean(normalized),
        }

    primary = event_metrics(
        [attack for attack in world.attacks if attack.primary]
    )
    boundary = event_metrics(
        [attack for attack in world.attacks if not attack.primary]
    )
    return {
        "primary_event_recall": primary["event_recall"],
        "primary_horizon_penalized_delay_s": primary["delay"],
        "primary_normalized_delay": primary["normalized"],
        "false_alarms_per_1000_clean_checks": (
            1000 * false_alarms / max(1, clean_checks)
        ),
        "boundary_event_recall": boundary["event_recall"],
    }


def summarize_rows(rows):
    return {
        "primary_event_recall": statistics.mean(
            row["primary_event_recall"] for row in rows
        ),
        "primary_horizon_penalized_delay_s": statistics.mean(
            row["primary_horizon_penalized_delay_s"]
            for row in rows
        ),
        "primary_normalized_delay": statistics.mean(
            row["primary_normalized_delay"] for row in rows
        ),
        "false_alarms_per_1000_clean_checks": statistics.mean(
            row["false_alarms_per_1000_clean_checks"]
            for row in rows
        ),
        "boundary_event_recall": statistics.mean(
            row["boundary_event_recall"] for row in rows
        ),
    }


def select_best(candidates):
    feasible = [
        item
        for item in candidates
        if item["summary"][
            "false_alarms_per_1000_clean_checks"
        ] <= FALSE_ALARM_CEILING
    ]
    if feasible:
        return max(
            feasible,
            key=lambda item: (
                item["summary"]["primary_event_recall"],
                -item["summary"][
                    "primary_horizon_penalized_delay_s"
                ],
                -item["summary"][
                    "false_alarms_per_1000_clean_checks"
                ],
            ),
        )
    return min(
        candidates,
        key=lambda item: (
            item["summary"][
                "false_alarms_per_1000_clean_checks"
            ],
            -item["summary"]["primary_event_recall"],
            item["summary"][
                "primary_horizon_penalized_delay_s"
            ],
        ),
    )


def tune(start_seed=TUNE_START_SEED, n_seeds=TUNE_SEEDS):
    seeds = list(range(start_seed, start_seed + n_seeds))
    worlds = [WorldOOD(seed) for seed in seeds]
    traces = [build_trace(world) for world in worlds]

    output = {
        "protocol": {
            "start_seed": start_seed,
            "n_seeds": n_seeds,
            "false_alarm_ceiling_per_1000": FALSE_ALARM_CEILING,
            "selection": (
                "maximize primary recall under false-alarm ceiling; "
                "then minimize horizon-penalized delay and false alarms"
            ),
            "stage15_e_cusum_frozen": True,
            "optimized_trace_replay": True,
        },
        "families": {},
        "selected": {},
    }

    for name, grid in FAMILIES.items():
        candidates = []
        for config in grid:
            rows = [
                evaluate_trace(world, trace, name, config)
                for world, trace in zip(worlds, traces)
            ]
            candidates.append(
                {
                    "config": config_to_dict(config),
                    "summary": summarize_rows(rows),
                }
            )

        best = select_best(candidates)
        output["families"][name] = {
            "grid_size": len(grid),
            "candidates": candidates,
        }
        output["selected"][name] = best

    champion_candidates = [
        {
            "name": name,
            "config": item["config"],
            "summary": item["summary"],
        }
        for name, item in output["selected"].items()
    ]
    feasible = [
        item
        for item in champion_candidates
        if item["summary"][
            "false_alarms_per_1000_clean_checks"
        ] <= FALSE_ALARM_CEILING
    ]
    if feasible:
        output["baseline_champion"] = max(
            feasible,
            key=lambda item: (
                item["summary"]["primary_event_recall"],
                -item["summary"][
                    "primary_horizon_penalized_delay_s"
                ],
                -item["summary"][
                    "false_alarms_per_1000_clean_checks"
                ],
            ),
        )
    else:
        output["baseline_champion"] = min(
            champion_candidates,
            key=lambda item: (
                item["summary"][
                    "false_alarms_per_1000_clean_checks"
                ],
                -item["summary"]["primary_event_recall"],
                item["summary"][
                    "primary_horizon_penalized_delay_s"
                ],
            ),
        )

    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start-seed", type=int, default=TUNE_START_SEED
    )
    parser.add_argument("--seeds", type=int, default=TUNE_SEEDS)
    parser.add_argument(
        "--output", default="stage16_tuning.json"
    )
    args = parser.parse_args()
    if args.seeds < 4:
        parser.error("At least four tuning seeds required")

    result = tune(args.start_seed, args.seeds)
    Path(args.output).write_text(
        json.dumps(result, indent=2), encoding="utf8"
    )

    print("# Stage 16 baseline tuning")
    print(
        f"Seeds: {args.start_seed}.."
        f"{args.start_seed + args.seeds - 1}"
    )
    for name, item in result["selected"].items():
        summary = item["summary"]
        print(
            name,
            json.dumps(item["config"], sort_keys=True),
            f"recall={summary['primary_event_recall']:.3f}",
            f"delay={summary['primary_horizon_penalized_delay_s']:.1f}s",
            f"fa/1000={summary['false_alarms_per_1000_clean_checks']:.3f}",
        )
    champion = result["baseline_champion"]
    print(
        "champion",
        champion["name"],
        json.dumps(champion["config"], sort_keys=True),
    )


if __name__ == "__main__":
    main()
