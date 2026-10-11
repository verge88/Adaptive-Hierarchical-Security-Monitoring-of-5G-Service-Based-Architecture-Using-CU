"""Stage 15 synthetic 5G-SBA simulator.

This stage deliberately makes the synthetic problem harder than the original
Stage-1 world: clean concept drift, zone-wide maintenance, local benign bursts,
heteroscedastic counter noise, sparse reconciliation outliers, and four attack
profiles (step, counter-only, ramp, intermittent).  Attack labels are retained
only by the evaluator; detectors receive observations and the fixed CU schedule.

The model is still synthetic and is not a 3GPP-compliant implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import random
import statistics
from typing import NamedTuple

STEP_SECONDS = 5
DURATION = 1800
WARMUP = 300
N_ZONES = 3
NF_PER_ZONE = 8
N_NF = N_ZONES * NF_PER_ZONE
CHALLENGES_PER_TICK = 4


@dataclass(frozen=True)
class Attack:
    nf: int
    start: int
    end: int
    kind: str
    fraction: float
    passive_gain: float


class Sample(NamedTuple):
    latency: float
    errors: float
    reported: int
    transit: int
    processing: float


def median(values):
    return statistics.median(values)


def robust_scale(values, center=None, floor=1e-6):
    if center is None:
        center = median(values)
    return max(
        floor,
        1.4826 * median([abs(value - center) for value in values]),
    )


def fixed_schedule(tick: int) -> list[int]:
    offset = (tick * CHALLENGES_PER_TICK) % N_NF
    return [(offset + j) % N_NF for j in range(CHALLENGES_PER_TICK)]


class WorldV2:
    """Matched synthetic world for detector comparisons.

    Every detector evaluated on the same seed sees the same samples and exactly
    the same fixed CU checks.  The random generator never depends on detector
    decisions, preventing policy-induced trace differences.
    """

    ATTACK_SPECS = (
        ("step", 0.105, 0.55),
        ("counter-only", 0.067, 0.03),
        ("ramp", 0.100, 0.24),
        ("intermittent", 0.125, 0.18),
    )

    def __init__(self, seed: int):
        self.seed = seed
        rng = random.Random(seed)

        attacked = rng.sample(range(N_NF), 12)
        self.attacks: list[Attack] = []
        self.attack_by_nf: dict[int, Attack] = {}
        for j, nf in enumerate(attacked):
            start = rng.randrange(500, 1200, STEP_SECONDS)
            duration = rng.choice((180, 210, 240, 270))
            kind, fraction, passive_gain = self.ATTACK_SPECS[j % len(self.ATTACK_SPECS)]
            attack = Attack(
                nf=nf,
                start=start,
                end=start + duration,
                kind=kind,
                fraction=fraction,
                passive_gain=passive_gain,
            )
            self.attacks.append(attack)
            self.attack_by_nf[nf] = attack

        self.bursts: list[tuple[int, int, int]] = []
        self.burst_by_nf = {nf: [] for nf in range(N_NF)}
        for nf in rng.sample(range(N_NF), 12):
            start = rng.randrange(450, 1250, STEP_SECONDS)
            end = start + rng.choice((90, 120, 150))
            self.bursts.append((nf, start, end))
            self.burst_by_nf[nf].append((start, end))

        self.maintenance: list[tuple[int, int, int]] = []
        for zone in range(N_ZONES):
            start = rng.randrange(650, 1100, STEP_SECONDS)
            self.maintenance.append(
                (zone, start, start + rng.choice((120, 180)))
            )

        self.samples: list[list[Sample]] = []
        for t in range(0, DURATION, STEP_SECONDS):
            seasonal = (
                0.55 * math.sin(2 * math.pi * t / 850)
                + 0.18 * math.sin(2 * math.pi * t / 275)
            )
            zone_common = [rng.gauss(0, 0.20) for _ in range(N_ZONES)]
            row: list[Sample] = []

            for nf in range(N_NF):
                zone = nf // NF_PER_ZONE
                attack = self.attack_by_nf.get(nf)
                active = bool(attack and attack.start <= t < attack.end)
                burst = any(
                    start <= t < end
                    for start, end in self.burst_by_nf[nf]
                )
                maintenance = any(
                    z == zone and start <= t < end
                    for z, start, end in self.maintenance
                )

                # Slow clean traffic drift after the first half of the run.
                drift = 0.00028 * max(0, t - 900)
                base = 155 + 16 * (nf % 6) + 10 * zone
                expected = max(
                    20,
                    int(
                        base * (1 + 0.16 * seasonal + drift)
                        + rng.gauss(0, 8)
                    ),
                )
                if burst:
                    expected = int(expected * 1.50)
                reported = max(1, expected + int(round(rng.gauss(0, 2.2))))

                attack_fraction = 0.0
                passive_gain = 0.0
                if active and attack is not None:
                    age = (t - attack.start) / max(
                        STEP_SECONDS, attack.end - attack.start
                    )
                    passive_gain = attack.passive_gain
                    if attack.kind in ("step", "counter-only"):
                        attack_fraction = attack.fraction
                    elif attack.kind == "ramp":
                        attack_fraction = 0.015 + (
                            attack.fraction - 0.015
                        ) * min(1.0, age / 0.70)
                    elif attack.kind == "intermittent":
                        attack_fraction = (
                            attack.fraction
                            if ((t - attack.start) // STEP_SECONDS) % 3
                            else 0.012
                        )
                    else:
                        raise AssertionError(attack.kind)

                # Independent observer noise grows with volume.  Rare clean
                # reconciliation outliers prevent trivial threshold separation.
                counter_sigma = 2.7 + 0.012 * reported
                counter_noise = rng.gauss(0, counter_sigma)
                if rng.random() < 0.0018:
                    counter_noise += rng.choice((-1, 1)) * (
                        0.042 * reported + rng.uniform(0, 3)
                    )
                transit = max(
                    1,
                    int(
                        round(
                            reported * (1 + attack_fraction)
                            + counter_noise
                        )
                    ),
                )

                latency = (
                    5.0
                    + 0.10 * (nf % NF_PER_ZONE)
                    + seasonal
                    + zone_common[zone]
                    + rng.gauss(0, 0.48)
                    + (1.25 if burst else 0)
                    + (0.85 if maintenance else 0)
                    + passive_gain
                )
                errors = max(
                    0.0,
                    0.55
                    + 0.16 * seasonal
                    + rng.gauss(0, 0.23)
                    + (0.68 if burst else 0)
                    + (0.38 if maintenance else 0)
                    + 0.45 * passive_gain,
                )
                processing = max(
                    0.1,
                    1.7
                    + rng.gauss(0, 0.30)
                    + (0.48 if burst else 0)
                    + (0.32 if maintenance else 0)
                    + 0.55 * passive_gain,
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
        return bool(attack and attack.start <= t < attack.end)


class PassiveRisk:
    """Robust warm-up features shared by both detector families."""

    def __init__(self, world: WorldV2):
        warm = world.samples[: WARMUP // STEP_SECONDS]
        self.lat_center = []
        self.lat_scale = []
        self.err_center = []
        self.err_scale = []
        self.spatial_center = []
        self.spatial_scale = []
        self.proc_center = []
        self.proc_scale = []
        self.ema = [0.0] * N_NF

        for nf in range(N_NF):
            latencies = [row[nf].latency for row in warm]
            errors = [row[nf].errors for row in warm]
            processing = [row[nf].processing for row in warm]
            start = (nf // NF_PER_ZONE) * NF_PER_ZONE
            spatial = [
                row[nf].latency
                - median(
                    [
                        row[j].latency
                        for j in range(start, start + NF_PER_ZONE)
                    ]
                )
                for row in warm
            ]
            self.lat_center.append(median(latencies))
            self.lat_scale.append(
                robust_scale(latencies, floor=0.25)
            )
            self.err_center.append(median(errors))
            self.err_scale.append(robust_scale(errors, floor=0.12))
            self.spatial_center.append(median(spatial))
            self.spatial_scale.append(
                robust_scale(spatial, floor=0.20)
            )
            self.proc_center.append(median(processing))
            self.proc_scale.append(
                robust_scale(processing, floor=0.16)
            )

    def risks(self, row: list[Sample]) -> list[float]:
        zone_medians = [
            median(
                [
                    row[i].latency
                    for i in range(
                        zone * NF_PER_ZONE,
                        (zone + 1) * NF_PER_ZONE,
                    )
                ]
            )
            for zone in range(N_ZONES)
        ]

        hierarchical = []
        for nf, sample in enumerate(row):
            lat_z = max(
                0.0,
                (sample.latency - self.lat_center[nf])
                / self.lat_scale[nf],
            )
            err_z = max(
                0.0,
                (sample.errors - self.err_center[nf])
                / self.err_scale[nf],
            )
            local = min(8.0, 0.6 * lat_z + 0.4 * err_z)
            self.ema[nf] = 0.7 * self.ema[nf] + 0.3 * local

            spatial_z = (
                (
                    sample.latency
                    - zone_medians[nf // NF_PER_ZONE]
                )
                - self.spatial_center[nf]
            ) / self.spatial_scale[nf]
            spatial_z = max(0.0, min(8.0, spatial_z))
            hierarchical.append(self.ema[nf] + 0.6 * spatial_z)
        return hierarchical

    def processing_z(self, nf: int, sample: Sample) -> float:
        return max(
            0.0,
            (sample.processing - self.proc_center[nf])
            / self.proc_scale[nf],
        )
