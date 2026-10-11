"""Shared Stage-16 evaluation utilities.

Metrics are event-oriented.  A missed event receives its own attack-window
length as the delay penalty; this is explicitly called horizon-penalized delay,
not statistical censoring.  Boundary observer-silent attacks are reported
separately from the primary integrity-visible suite.
"""
from __future__ import annotations

import statistics

from .stage15_simulation import (
    CHALLENGES_PER_TICK,
    DURATION,
    STEP_SECONDS,
    WARMUP,
)
from .stage16_simulation import (
    BOUNDARY_KIND,
    PRIMARY_KINDS,
    WorldOOD,
    fixed_schedule,
)


def evaluate_detector(world: WorldOOD, detector) -> dict:
    found = {attack.nf: None for attack in world.attacks}
    false_alarms = 0
    clean_checks = 0
    alarms_in_attack = 0

    for tick, row in enumerate(world.samples):
        t = tick * STEP_SECONDS
        if t < WARMUP:
            continue

        hierarchical = detector.risk.risks(row)
        for nf in fixed_schedule(tick):
            alert = detector.observe(
                nf, row[nf], hierarchical[nf]
            )
            attacked = world.active_attack(nf, t)
            if attacked:
                if alert:
                    alarms_in_attack += 1
                    if found[nf] is None:
                        found[nf] = t
            else:
                clean_checks += 1
                false_alarms += int(alert)

    def event_metrics(attacks):
        if not attacks:
            return {
                "events": 0,
                "event_recall": 0.0,
                "mean_horizon_penalized_delay_s": 0.0,
                "mean_normalized_delay": 0.0,
                "mean_detected_delay_s": None,
            }

        delays = []
        normalized = []
        detected_delays = []
        detected = 0
        for attack in attacks:
            duration = attack.end - attack.start
            alarm = found[attack.nf]
            if alarm is None:
                delay = duration
            else:
                detected += 1
                delay = max(0, alarm - attack.start)
                detected_delays.append(delay)
            delays.append(delay)
            normalized.append(delay / max(1, duration))

        return {
            "events": len(attacks),
            "event_recall": detected / len(attacks),
            "mean_horizon_penalized_delay_s": (
                statistics.mean(delays)
            ),
            "mean_normalized_delay": statistics.mean(
                normalized
            ),
            "mean_detected_delay_s": (
                statistics.mean(detected_delays)
                if detected_delays
                else None
            ),
        }

    primary_attacks = [
        attack for attack in world.attacks if attack.primary
    ]
    boundary_attacks = [
        attack for attack in world.attacks if not attack.primary
    ]
    primary = event_metrics(primary_attacks)
    boundary = event_metrics(boundary_attacks)

    per_kind = {}
    for kind in (*PRIMARY_KINDS, BOUNDARY_KIND):
        per_kind[kind] = event_metrics(
            [
                attack
                for attack in world.attacks
                if attack.kind == kind
            ]
        )

    probes = (
        (DURATION - WARMUP)
        // STEP_SECONDS
        * CHALLENGES_PER_TICK
    )
    if clean_checks + sum(
        1
        for tick in range(
            WARMUP // STEP_SECONDS,
            DURATION // STEP_SECONDS,
        )
        for nf in fixed_schedule(tick)
        if world.active_attack(nf, tick * STEP_SECONDS)
    ) != probes:
        raise AssertionError(
            "Stage16 evaluator check accounting mismatch"
        )

    return {
        "seed": world.seed,
        "primary_event_recall": primary["event_recall"],
        "primary_horizon_penalized_delay_s": (
            primary["mean_horizon_penalized_delay_s"]
        ),
        "primary_normalized_delay": (
            primary["mean_normalized_delay"]
        ),
        "primary_detected_delay_s": (
            primary["mean_detected_delay_s"]
        ),
        "boundary_event_recall": boundary["event_recall"],
        "boundary_horizon_penalized_delay_s": (
            boundary["mean_horizon_penalized_delay_s"]
        ),
        "false_alarms_per_1000_clean_checks": (
            1000
            * false_alarms
            / max(1, clean_checks)
        ),
        "false_alarms": false_alarms,
        "clean_checks": clean_checks,
        "alarms_in_attack": alarms_in_attack,
        "probes": probes,
        "per_kind": per_kind,
    }
