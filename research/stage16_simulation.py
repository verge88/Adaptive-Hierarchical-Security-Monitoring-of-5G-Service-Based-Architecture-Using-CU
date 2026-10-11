"""Stage 16 out-of-distribution synthetic SBA benchmark.

The Stage-15 detector is frozen.  This world intentionally changes both clean
traffic and attack distributions so the next experiment measures robustness
rather than another interpolation over the Stage-15 generator.

Primary suite: integrity-visible attacks that remain inside the repository's
independent-observer threat model but use unseen amplitudes, directions and
temporal shapes.  A secondary observer-silent semantic attack is included as a
boundary test and is reported separately because it violates the assumption
that the trusted transit observer sees the security-relevant discrepancy.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import random

from .stage15_simulation import (
    CHALLENGES_PER_TICK,
    DURATION,
    NF_PER_ZONE,
    N_NF,
    N_ZONES,
    STEP_SECONDS,
    WARMUP,
    Sample,
)


@dataclass(frozen=True)
class OODAttack:
    nf: int
    start: int
    end: int
    kind: str
    direction: int
    peak_fraction: float
    passive_gain: float
    primary: bool = True


PRIMARY_KINDS = (
    "micro_step",
    "reverse_step",
    "slow_nonlinear_ramp",
    "sparse_bursts",
)
BOUNDARY_KIND = "observer_silent_semantic"


def fixed_schedule(tick: int) -> list[int]:
    offset = (tick * CHALLENGES_PER_TICK) % N_NF
    return [(offset + j) % N_NF for j in range(CHALLENGES_PER_TICK)]


class WorldOOD:
    """Distribution-shifted matched world.

    Important differences from Stage 15:
    - attack amplitudes are sampled continuously instead of fixed constants;
    - both under-reporting and over-reporting are present;
    - nonlinear ramps and sparse burst trains replace the old exact patterns;
    - clean counter variance increases after warm-up;
    - clean reconciliation outliers are more frequent and heavy-tailed;
    - maintenance and burst amplitudes/durations are randomized;
    - seasonality periods differ from Stage 15.

    Detector decisions never influence the generated trace.
    """

    def __init__(self, seed: int):
        self.seed = seed
        rng = random.Random(seed)

        attacked = rng.sample(range(N_NF), 15)
        self.attacks: list[OODAttack] = []
        self.attack_by_nf: dict[int, OODAttack] = {}

        specs = list(PRIMARY_KINDS) * 3 + [BOUNDARY_KIND] * 3
        rng.shuffle(specs)
        for nf, kind in zip(attacked, specs):
            start = rng.randrange(520, 1160, STEP_SECONDS)
            duration = rng.choice((165, 195, 225, 255, 285))
            if kind == "micro_step":
                peak = rng.uniform(0.045, 0.068)
                direction = 1
                passive = rng.uniform(0.03, 0.16)
                primary = True
            elif kind == "reverse_step":
                peak = rng.uniform(0.050, 0.080)
                direction = -1
                passive = rng.uniform(0.02, 0.14)
                primary = True
            elif kind == "slow_nonlinear_ramp":
                peak = rng.uniform(0.075, 0.110)
                direction = rng.choice((-1, 1))
                passive = rng.uniform(0.08, 0.28)
                primary = True
            elif kind == "sparse_bursts":
                peak = rng.uniform(0.095, 0.140)
                direction = rng.choice((-1, 1))
                passive = rng.uniform(0.04, 0.22)
                primary = True
            elif kind == BOUNDARY_KIND:
                peak = 0.0
                direction = 1
                passive = rng.uniform(0.65, 1.05)
                primary = False
            else:
                raise AssertionError(kind)

            attack = OODAttack(
                nf=nf,
                start=start,
                end=start + duration,
                kind=kind,
                direction=direction,
                peak_fraction=peak,
                passive_gain=passive,
                primary=primary,
            )
            self.attacks.append(attack)
            self.attack_by_nf[nf] = attack

        self.bursts: list[tuple[int, int, int, float]] = []
        self.burst_by_nf = {nf: [] for nf in range(N_NF)}
        for nf in rng.sample(range(N_NF), 14):
            start = rng.randrange(430, 1300, STEP_SECONDS)
            duration = rng.choice((60, 85, 110, 140, 175))
            gain = rng.uniform(0.65, 1.75)
            item = (nf, start, start + duration, gain)
            self.bursts.append(item)
            self.burst_by_nf[nf].append(item[1:])

        self.maintenance: list[tuple[int, int, int, float]] = []
        for zone in range(N_ZONES):
            for _ in range(2):
                start = rng.randrange(600, 1320, STEP_SECONDS)
                duration = rng.choice((75, 120, 165, 210))
                gain = rng.uniform(0.35, 1.15)
                self.maintenance.append(
                    (zone, start, start + duration, gain)
                )

        self.samples: list[list[Sample]] = []
        for t in range(0, DURATION, STEP_SECONDS):
            seasonal = (
                0.42 * math.sin(2 * math.pi * t / 710)
                + 0.24 * math.sin(2 * math.pi * t / 331)
                + 0.10 * math.sin(2 * math.pi * t / 119)
            )
            zone_common = [
                rng.gauss(0, 0.18 + 0.00005 * t)
                for _ in range(N_ZONES)
            ]
            row: list[Sample] = []

            for nf in range(N_NF):
                zone = nf // NF_PER_ZONE
                attack = self.attack_by_nf.get(nf)
                active = bool(
                    attack and attack.start <= t < attack.end
                )
                burst_gain = max(
                    (
                        gain
                        for start, end, gain
                        in self.burst_by_nf[nf]
                        if start <= t < end
                    ),
                    default=0.0,
                )
                maintenance_gain = max(
                    (
                        gain
                        for z, start, end, gain
                        in self.maintenance
                        if z == zone and start <= t < end
                    ),
                    default=0.0,
                )

                # Clean traffic undergoes nonlinear load drift after warm-up.
                load_drift = (
                    1.0
                    + 0.00018 * max(0, t - 650)
                    + 0.00000011 * max(0, t - 1050) ** 2
                )
                base = 145 + 17 * (nf % 6) + 12 * zone
                honest = max(
                    20,
                    int(
                        (
                            base * (1 + 0.14 * seasonal)
                            + rng.gauss(0, 9.5)
                        )
                        * load_drift
                    ),
                )
                if burst_gain:
                    honest = int(
                        honest * (1 + 0.25 * burst_gain)
                    )

                # Independent trusted observer approximates the honest
                # transaction count, with post-warmup heteroscedasticity.
                noise_multiplier = (
                    1.0
                    if t < 850
                    else 1.0 + 0.00075 * (t - 850)
                )
                sigma = (
                    2.4 + 0.014 * honest
                ) * noise_multiplier
                transit_noise = rng.gauss(0, sigma)
                # More frequent heavy-tailed clean reconciliation errors than
                # Stage 15.  These are intentionally difficult false alarms.
                outlier_p = 0.0015 if t < WARMUP else 0.0055
                if rng.random() < outlier_p:
                    transit_noise += rng.choice((-1, 1)) * (
                        rng.uniform(0.035, 0.075) * honest
                        + rng.uniform(0, 5)
                    )
                transit = max(
                    1, int(round(honest + transit_noise))
                )

                attack_fraction = 0.0
                passive_gain = 0.0
                if active and attack is not None:
                    passive_gain = attack.passive_gain
                    age = (t - attack.start) / max(
                        STEP_SECONDS,
                        attack.end - attack.start,
                    )
                    if attack.kind in (
                        "micro_step",
                        "reverse_step",
                    ):
                        attack_fraction = attack.peak_fraction
                    elif attack.kind == "slow_nonlinear_ramp":
                        attack_fraction = (
                            0.006
                            + (
                                attack.peak_fraction - 0.006
                            )
                            * min(1.0, age / 0.92) ** 1.8
                        )
                    elif attack.kind == "sparse_bursts":
                        phase = (
                            (t - attack.start)
                            // STEP_SECONDS
                        ) % 7
                        attack_fraction = (
                            attack.peak_fraction
                            if phase in (1, 2, 5)
                            else rng.uniform(0.0, 0.012)
                        )
                    elif attack.kind == BOUNDARY_KIND:
                        attack_fraction = 0.0
                    else:
                        raise AssertionError(attack.kind)

                # The compromised NF falsifies its report.  Positive direction
                # over-reports, negative direction under-reports.
                report_direction = (
                    attack.direction
                    if active and attack is not None
                    else 1
                )
                reported = max(
                    1,
                    int(
                        round(
                            honest
                            * (
                                1
                                + report_direction
                                * attack_fraction
                            )
                            + rng.gauss(0, 2.4)
                        )
                    ),
                )

                latency = (
                    4.9
                    + 0.11 * (nf % NF_PER_ZONE)
                    + seasonal
                    + zone_common[zone]
                    + rng.gauss(0, 0.50)
                    + 0.85 * burst_gain
                    + maintenance_gain
                    + passive_gain
                )
                errors = max(
                    0.0,
                    0.52
                    + 0.14 * seasonal
                    + rng.gauss(0, 0.25)
                    + 0.40 * burst_gain
                    + 0.36 * maintenance_gain
                    + 0.42 * passive_gain,
                )
                processing = max(
                    0.1,
                    1.65
                    + rng.gauss(0, 0.32)
                    + 0.33 * burst_gain
                    + 0.28 * maintenance_gain
                    + 0.50 * passive_gain,
                )
                row.append(
                    Sample(
                        latency,
                        errors,
                        reported,
                        transit,
                        processing,
                    )
                )

            self.samples.append(row)

    def active_attack(self, nf: int, t: int) -> bool:
        attack = self.attack_by_nf.get(nf)
        return bool(
            attack and attack.start <= t < attack.end
        )
