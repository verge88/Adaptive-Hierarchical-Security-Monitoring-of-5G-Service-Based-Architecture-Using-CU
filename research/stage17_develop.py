"""Stage-17 development-only tuning.

This file may inspect development seeds 6001..6040. It must never inspect the
predeclared final block 7001..7200.

Both the new drift-adaptive e-Page detector and the Page-Hinkley comparator are
tuned on exactly the same development worlds and the same calibrated feature
traces. Selection objective:

1. mean false alarms <= 0.50 / 1000 clean checks;
2. maximize primary OOD event recall;
3. minimize horizon-penalized delay;
4. minimize false alarms.

The Stage-16 evaluation seeds 5001..5200 are not used.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import statistics

from .stage15_detector import power_betting_mixture, upper_tail_rank
from .stage15_simulation import N_NF, STEP_SECONDS, WARMUP
from .stage16_detectors import CalibratedSurprise, PageHinkleyConfig
from .stage16_simulation import WorldOOD, fixed_schedule
from .stage17_detector import (
    ADAPTIVE_EPAGE_GRID,
    E_ASSISTED_PAGE_GRID,
    E_CONFIRMED_PAGE_GRID,
    DIRECTIONAL_E_GRID,
    AdaptiveEPageConfig,
    EAssistedPageConfig,
    EConfirmedPageConfig,
    DirectionalEConfig,
    lower_tail_rank,
    signed_discrepancy,
)

DEV_START_SEED = 6001
DEV_SEEDS = 40
FINAL_START_SEED = 7001
FINAL_SEEDS = 200
FALSE_ALARM_CEILING = 0.50

PAGE_HINKLEY_DEV_GRID = tuple(
    PageHinkleyConfig(
        delta=delta,
        threshold=threshold,
        integrity_gate_p=gate,
        mean_alpha=alpha,
    )
    for delta in (0.25, 0.35, 0.50, 0.65, 0.80)
    for threshold in (6.0, 8.0, 9.5, 11.0, 13.5)
    for gate in (0.03, 0.045, 0.06, 0.08, 0.10)
    for alpha in (0.03, 0.05, 0.07, 0.10)
)


def calibration_log_reference(feature, joint_weight=0.30):
    values = []
    for d, joint in zip(
        feature.integrity_calibration,
        feature.joint_calibration,
    ):
        p_i = upper_tail_rank(
            feature.integrity_calibration, d
        )
        p_j = upper_tail_rank(
            feature.joint_calibration, joint
        )
        e_i = power_betting_mixture(p_i)
        e_j = power_betting_mixture(p_j)
        e_value = (
            (1.0 - joint_weight) * e_i
            + joint_weight * e_j
        )
        values.append(math.log(max(1e-12, e_value)))
    return statistics.mean(values)


def build_trace(world):
    feature = CalibratedSurprise(world)
    warm_reference = calibration_log_reference(feature)
    checks = []

    for tick, row in enumerate(world.samples):
        t = tick * STEP_SECONDS
        if t < WARMUP:
            continue
        hierarchical = feature.risk.risks(row)
        for nf in fixed_schedule(tick):
            surprise, p_i, p_j = feature.evidence_features(
                nf, row[nf], hierarchical[nf]
            )
            e_i = power_betting_mixture(p_i)
            e_j = power_betting_mixture(p_j)
            e_value = 0.70 * e_i + 0.30 * e_j
            checks.append(
                (
                    nf,
                    t,
                    surprise,
                    p_i,
                    math.log(max(1e-12, e_value)),
                )
            )

    signed_calibration = []
    for tick, row in enumerate(
        world.samples[: WARMUP // STEP_SECONDS]
    ):
        for nf in fixed_schedule(tick):
            signed_calibration.append(
                signed_discrepancy(row[nf])
            )

    directional = []
    for nf, t, _, _, _ in checks:
        sample = world.samples[t // STEP_SECONDS][nf]
        value = signed_discrepancy(sample)
        p_positive = upper_tail_rank(
            signed_calibration, value
        )
        p_negative = lower_tail_rank(
            signed_calibration, value
        )
        directional.append(
            (nf, t, p_positive, p_negative)
        )

    return {
        "warm_reference": warm_reference,
        "checks": checks,
        "directional": directional,
    }


def event_summary(world, found, false_alarms, clean_checks):
    primary = [
        attack for attack in world.attacks if attack.primary
    ]
    detected = 0
    delays = []
    for attack in primary:
        duration = attack.end - attack.start
        alarm = found[attack.nf]
        if alarm is None:
            delay = duration
        else:
            detected += 1
            delay = max(0, alarm - attack.start)
        delays.append(delay)

    return {
        "event_recall": detected / len(primary),
        "horizon_penalized_delay_s": statistics.mean(
            delays
        ),
        "false_alarms_per_1000": (
            1000 * false_alarms / max(1, clean_checks)
        ),
    }


def evaluate_hybrid_trace(world, trace, config):
    reference = [trace["warm_reference"]] * N_NF
    cumulative = [0.0] * N_NF
    minimum = [0.0] * N_NF
    found = {attack.nf: None for attack in world.attacks}
    false_alarms = clean_checks = 0

    for nf, t, _, p_i, log_e in trace["checks"]:
        cumulative[nf] += (
            log_e - reference[nf] - config.delta
        )
        minimum[nf] = min(
            minimum[nf], cumulative[nf]
        )
        statistic = cumulative[nf] - minimum[nf]
        alert = (
            statistic >= config.threshold
            and p_i <= config.integrity_gate_p
        )

        if world.active_attack(nf, t):
            if alert and found[nf] is None:
                found[nf] = t
        else:
            clean_checks += 1
            false_alarms += int(alert)

        if alert:
            cumulative[nf] = 0.0
            minimum[nf] = 0.0
        else:
            bounded = min(
                log_e,
                reference[nf] + config.update_log_cap,
            )
            reference[nf] = (
                (1.0 - config.mean_alpha)
                * reference[nf]
                + config.mean_alpha * bounded
            )

    return event_summary(
        world, found, false_alarms, clean_checks
    )


def evaluate_e_assisted_page_trace(world, trace, config):
    mean = [1.0] * N_NF
    cumulative = [0.0] * N_NF
    minimum = [0.0] * N_NF
    e_memory = [0.0] * N_NF
    found = {attack.nf: None for attack in world.attacks}
    false_alarms = clean_checks = 0

    for nf, t, surprise, p_i, log_e in trace["checks"]:
        mean[nf] = (
            (1.0 - config.mean_alpha) * mean[nf]
            + config.mean_alpha * surprise
        )
        cumulative[nf] += (
            surprise - mean[nf] - config.delta
        )
        minimum[nf] = min(minimum[nf], cumulative[nf])
        ph_statistic = cumulative[nf] - minimum[nf]

        positive_log_e = max(0.0, log_e)
        e_memory[nf] = (
            config.e_decay * e_memory[nf]
            + positive_log_e
        )
        discount = min(
            config.max_threshold_discount,
            config.e_gain * e_memory[nf],
        )
        effective_threshold = (
            config.threshold * (1.0 - discount)
        )
        alert = (
            ph_statistic >= effective_threshold
            and p_i <= config.integrity_gate_p
        )

        if world.active_attack(nf, t):
            if alert and found[nf] is None:
                found[nf] = t
        else:
            clean_checks += 1
            false_alarms += int(alert)

        if alert:
            cumulative[nf] = 0.0
            minimum[nf] = 0.0
            e_memory[nf] = 0.0

    return event_summary(
        world, found, false_alarms, clean_checks
    )


def evaluate_e_confirmed_page_trace(world, trace, config):
    mean = [1.0] * N_NF
    cumulative = [0.0] * N_NF
    minimum = [0.0] * N_NF
    e_memory = [0.0] * N_NF
    found = {attack.nf: None for attack in world.attacks}
    false_alarms = clean_checks = 0

    for nf, t, surprise, p_i, log_e in trace["checks"]:
        mean[nf] = (
            (1.0 - config.mean_alpha) * mean[nf]
            + config.mean_alpha * surprise
        )
        cumulative[nf] += (
            surprise - mean[nf] - config.delta
        )
        minimum[nf] = min(minimum[nf], cumulative[nf])
        ph_statistic = cumulative[nf] - minimum[nf]

        e_memory[nf] = (
            config.e_decay * e_memory[nf]
            + max(0.0, log_e)
        )
        alert = (
            ph_statistic >= config.threshold
            and p_i <= config.integrity_gate_p
            and e_memory[nf]
            >= config.e_confirm_threshold
        )

        if world.active_attack(nf, t):
            if alert and found[nf] is None:
                found[nf] = t
        else:
            clean_checks += 1
            false_alarms += int(alert)

        if alert:
            cumulative[nf] = 0.0
            minimum[nf] = 0.0
            e_memory[nf] = 0.0

    return event_summary(
        world, found, false_alarms, clean_checks
    )


def evaluate_directional_trace(world, trace, config):
    positive = [0.0] * N_NF
    negative = [0.0] * N_NF
    found = {attack.nf: None for attack in world.attacks}
    false_alarms = clean_checks = 0

    for nf, t, p_positive, p_negative in trace["directional"]:
        log_e_positive = math.log(
            max(1e-12, power_betting_mixture(p_positive))
        )
        log_e_negative = math.log(
            max(1e-12, power_betting_mixture(p_negative))
        )
        positive[nf] = max(
            0.0,
            config.decay * positive[nf]
            + log_e_positive
            - config.reference,
        )
        negative[nf] = max(
            0.0,
            config.decay * negative[nf]
            + log_e_negative
            - config.reference,
        )

        alert = (
            (
                positive[nf] >= config.threshold
                and p_positive <= config.direction_gate_p
            )
            or (
                negative[nf] >= config.threshold
                and p_negative <= config.direction_gate_p
            )
        )

        if world.active_attack(nf, t):
            if alert and found[nf] is None:
                found[nf] = t
        else:
            clean_checks += 1
            false_alarms += int(alert)

        if alert:
            positive[nf] = 0.0
            negative[nf] = 0.0

    return event_summary(
        world, found, false_alarms, clean_checks
    )


def evaluate_page_hinkley_trace(world, trace, config):
    mean = [1.0] * N_NF
    cumulative = [0.0] * N_NF
    minimum = [0.0] * N_NF
    found = {attack.nf: None for attack in world.attacks}
    false_alarms = clean_checks = 0

    for nf, t, surprise, p_i, _ in trace["checks"]:
        mean[nf] = (
            (1.0 - config.mean_alpha) * mean[nf]
            + config.mean_alpha * surprise
        )
        cumulative[nf] += (
            surprise - mean[nf] - config.delta
        )
        minimum[nf] = min(
            minimum[nf], cumulative[nf]
        )
        statistic = cumulative[nf] - minimum[nf]
        alert = (
            statistic >= config.threshold
            and p_i <= config.integrity_gate_p
        )

        if world.active_attack(nf, t):
            if alert and found[nf] is None:
                found[nf] = t
        else:
            clean_checks += 1
            false_alarms += int(alert)

        if alert:
            cumulative[nf] = 0.0
            minimum[nf] = 0.0

    return event_summary(
        world, found, false_alarms, clean_checks
    )


def summarize(rows):
    return {
        "event_recall": statistics.mean(
            row["event_recall"] for row in rows
        ),
        "horizon_penalized_delay_s": statistics.mean(
            row["horizon_penalized_delay_s"] for row in rows
        ),
        "false_alarms_per_1000": statistics.mean(
            row["false_alarms_per_1000"] for row in rows
        ),
    }


def select_best(candidates):
    feasible = [
        item
        for item in candidates
        if item["summary"]["false_alarms_per_1000"]
        <= FALSE_ALARM_CEILING
    ]
    pool = feasible if feasible else candidates
    if feasible:
        return max(
            pool,
            key=lambda item: (
                item["summary"]["event_recall"],
                -item["summary"][
                    "horizon_penalized_delay_s"
                ],
                -item["summary"][
                    "false_alarms_per_1000"
                ],
            ),
        )
    return min(
        pool,
        key=lambda item: (
            item["summary"]["false_alarms_per_1000"],
            -item["summary"]["event_recall"],
            item["summary"]["horizon_penalized_delay_s"],
        ),
    )


def config_dict(config):
    return dict(config.__dict__)


def develop(start_seed=DEV_START_SEED, n_seeds=DEV_SEEDS):
    if (
        start_seed <= 5200
        and start_seed + n_seeds - 1 >= 5001
    ):
        raise ValueError(
            "Stage-16 evaluation seeds 5001..5200 are forbidden"
        )
    if (
        start_seed <= FINAL_START_SEED + FINAL_SEEDS - 1
        and start_seed + n_seeds - 1 >= FINAL_START_SEED
    ):
        raise ValueError(
            "Stage-17 final seeds 7001..7200 are forbidden during development"
        )

    worlds = [
        WorldOOD(seed)
        for seed in range(start_seed, start_seed + n_seeds)
    ]
    traces = [build_trace(world) for world in worlds]

    hybrid_candidates = []
    for config in ADAPTIVE_EPAGE_GRID:
        rows = [
            evaluate_hybrid_trace(world, trace, config)
            for world, trace in zip(worlds, traces)
        ]
        hybrid_candidates.append(
            {
                "config": config_dict(config),
                "summary": summarize(rows),
            }
        )

    assisted_candidates = []
    for config in E_ASSISTED_PAGE_GRID:
        rows = [
            evaluate_e_assisted_page_trace(
                world, trace, config
            )
            for world, trace in zip(worlds, traces)
        ]
        assisted_candidates.append(
            {
                "config": config_dict(config),
                "summary": summarize(rows),
            }
        )

    confirmed_candidates = []
    for config in E_CONFIRMED_PAGE_GRID:
        rows = [
            evaluate_e_confirmed_page_trace(
                world, trace, config
            )
            for world, trace in zip(worlds, traces)
        ]
        confirmed_candidates.append(
            {
                "config": config_dict(config),
                "summary": summarize(rows),
            }
        )

    directional_candidates = []
    for config in DIRECTIONAL_E_GRID:
        rows = [
            evaluate_directional_trace(
                world, trace, config
            )
            for world, trace in zip(worlds, traces)
        ]
        directional_candidates.append(
            {
                "config": config_dict(config),
                "summary": summarize(rows),
            }
        )

    ph_candidates = []
    for config in PAGE_HINKLEY_DEV_GRID:
        rows = [
            evaluate_page_hinkley_trace(
                world, trace, config
            )
            for world, trace in zip(worlds, traces)
        ]
        ph_candidates.append(
            {
                "config": config_dict(config),
                "summary": summarize(rows),
            }
        )

    best_adaptive_e_page = select_best(hybrid_candidates)
    best_assisted = select_best(assisted_candidates)
    best_confirmed = select_best(confirmed_candidates)
    best_directional = select_best(directional_candidates)
    best_ph = select_best(ph_candidates)
    best_hybrid = select_best(
        [
            {
                "family": "adaptive_e_page",
                **best_adaptive_e_page,
            },
            {
                "family": "e_assisted_page_hinkley",
                **best_assisted,
            },
            {
                "family": "e_confirmed_page_hinkley",
                **best_confirmed,
            },
            {
                "family": "directional_e_process",
                **best_directional,
            },
        ]
    )

    return {
        "protocol": {
            "development_start_seed": start_seed,
            "development_seeds": n_seeds,
            "forbidden_stage16_eval": [5001, 5200],
            "predeclared_final_block": [7001, 7200],
            "false_alarm_ceiling_per_1000": (
                FALSE_ALARM_CEILING
            ),
        },
        "adaptive_e_page_grid_size": len(ADAPTIVE_EPAGE_GRID),
        "e_assisted_page_grid_size": len(E_ASSISTED_PAGE_GRID),
        "e_confirmed_page_grid_size": len(E_CONFIRMED_PAGE_GRID),
        "directional_e_grid_size": len(DIRECTIONAL_E_GRID),
        "page_hinkley_grid_size": len(
            PAGE_HINKLEY_DEV_GRID
        ),
        "selected_adaptive_e_page": best_adaptive_e_page,
        "selected_e_assisted_page_hinkley": best_assisted,
        "selected_e_confirmed_page_hinkley": best_confirmed,
        "selected_directional_e_process": best_directional,
        "selected_hybrid": best_hybrid,
        "selected_page_hinkley": best_ph,
        "development_effect_hybrid_minus_page_hinkley": {
            "event_recall": (
                best_hybrid["summary"]["event_recall"]
                - best_ph["summary"]["event_recall"]
            ),
            "horizon_penalized_delay_s": (
                best_hybrid["summary"][
                    "horizon_penalized_delay_s"
                ]
                - best_ph["summary"][
                    "horizon_penalized_delay_s"
                ]
            ),
            "false_alarms_per_1000": (
                best_hybrid["summary"][
                    "false_alarms_per_1000"
                ]
                - best_ph["summary"][
                    "false_alarms_per_1000"
                ]
            ),
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start-seed",
        type=int,
        default=DEV_START_SEED,
    )
    parser.add_argument(
        "--seeds", type=int, default=DEV_SEEDS
    )
    parser.add_argument(
        "--output",
        default="stage17_development.json",
    )
    args = parser.parse_args()

    result = develop(args.start_seed, args.seeds)
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )

    print("# Stage 17 development")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
