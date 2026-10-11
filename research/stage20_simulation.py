"""Stage 20 environment-randomized signed-integrity benchmark.

Stage 19 final showed that sparse recall generalized while the clean
false-alarm rate did not. Stage 20 therefore develops on deliberately diverse
clean environments instead of a single nuisance distribution.

No Stage-19 final seed or Stage-18 live artifact is read.

Development block: 11001..11060.
Predeclared untouched final block: 12001..12200.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import random

WARMUP_TICKS = 40
EPISODE_TICKS = 18
GAP_TICKS = 10
REPETITIONS_PER_KIND = 4

PERSISTENT_KINDS = (
    "persistent_positive",
    "persistent_negative",
)
SPARSE_KINDS = (
    "sparse_positive",
    "sparse_negative",
    "cluster_sparse_positive",
    "cluster_sparse_negative",
)
ALL_KINDS = PERSISTENT_KINDS + SPARSE_KINDS

ENVIRONMENT_MODES = (
    "nominal",
    "high_drift",
    "high_outlier",
    "variance_shift",
    "biased_regime",
)


@dataclass(frozen=True)
class EnvironmentSpec:
    mode: str
    ar_phi: float
    base_sigma: float
    variance_slope: float
    post_variance_jump: float
    drift_amp_1: float
    drift_amp_2: float
    outlier_p: float
    outlier_low: float
    outlier_high: float
    regime_bias: float


@dataclass(frozen=True)
class Stage20Episode:
    episode: int
    kind: str
    start_tick: int
    end_tick: int
    direction: int
    pulse_ticks: tuple[int, ...]
    amplitude: float

    @property
    def sparse(self) -> bool:
        return self.kind in SPARSE_KINDS


def environment_for_seed(seed: int) -> EnvironmentSpec:
    mode = ENVIRONMENT_MODES[seed % len(ENVIRONMENT_MODES)]
    rng = random.Random(seed * 2020 + 17)

    common = dict(
        mode=mode,
        ar_phi=rng.uniform(0.45, 0.78),
        base_sigma=rng.uniform(0.0048, 0.0080),
        variance_slope=rng.uniform(0.0001, 0.0007),
        post_variance_jump=rng.uniform(1.0, 1.35),
        drift_amp_1=rng.uniform(0.0015, 0.0045),
        drift_amp_2=rng.uniform(0.0010, 0.0035),
        outlier_p=rng.uniform(0.004, 0.009),
        outlier_low=rng.uniform(0.035, 0.050),
        outlier_high=rng.uniform(0.065, 0.090),
        regime_bias=rng.uniform(-0.004, 0.004),
    )

    if mode == "high_drift":
        common["drift_amp_1"] = rng.uniform(0.0055, 0.0100)
        common["drift_amp_2"] = rng.uniform(0.0035, 0.0070)
        common["regime_bias"] = rng.uniform(-0.012, 0.012)
    elif mode == "high_outlier":
        common["outlier_p"] = rng.uniform(0.012, 0.024)
        common["outlier_low"] = rng.uniform(0.045, 0.070)
        common["outlier_high"] = rng.uniform(0.090, 0.140)
    elif mode == "variance_shift":
        common["post_variance_jump"] = rng.uniform(1.55, 2.35)
        common["variance_slope"] = rng.uniform(0.0007, 0.0017)
    elif mode == "biased_regime":
        common["regime_bias"] = rng.choice((-1, 1)) * rng.uniform(
            0.010, 0.022
        )
        common["ar_phi"] = rng.uniform(0.65, 0.88)

    return EnvironmentSpec(**common)


class EnvironmentRandomizedWorld:
    """Matched environment-randomized world with evaluator-only labels."""

    def __init__(self, seed: int):
        self.seed = seed
        self.environment = environment_for_seed(seed)
        rng = random.Random(seed * 20020 + 53)

        kinds = [
            kind
            for kind in ALL_KINDS
            for _ in range(REPETITIONS_PER_KIND)
        ]
        rng.shuffle(kinds)

        self.episodes: list[Stage20Episode] = []
        cursor = WARMUP_TICKS
        for episode_id, kind in enumerate(kinds):
            start = cursor
            end = start + EPISODE_TICKS
            direction = 1 if kind.endswith("positive") else -1

            if kind in PERSISTENT_KINDS:
                pulses = tuple(range(EPISODE_TICKS))
                amplitude = rng.uniform(0.040, 0.090)
            elif kind.startswith("cluster_sparse"):
                first = rng.randrange(1, 6)
                second = rng.randrange(10, 15)
                pulses = tuple(
                    sorted(
                        {
                            first,
                            min(first + 1, EPISODE_TICKS - 1),
                            second,
                            min(second + 1, EPISODE_TICKS - 1),
                        }
                    )
                )
                amplitude = rng.uniform(0.080, 0.155)
            else:
                count = rng.choice((3, 4, 5))
                candidates = list(range(1, EPISODE_TICKS - 1))
                rng.shuffle(candidates)
                selected: list[int] = []
                for candidate in candidates:
                    if all(
                        abs(candidate - old) >= 2
                        for old in selected
                    ):
                        selected.append(candidate)
                        if len(selected) == count:
                            break
                if len(selected) != count:
                    raise AssertionError("Could not place sparse pulses")
                pulses = tuple(sorted(selected))
                amplitude = rng.uniform(0.090, 0.165)

            self.episodes.append(
                Stage20Episode(
                    episode=episode_id,
                    kind=kind,
                    start_tick=start,
                    end_tick=end,
                    direction=direction,
                    pulse_ticks=pulses,
                    amplitude=amplitude,
                )
            )
            cursor = end + GAP_TICKS

        self.total_ticks = cursor

        by_tick = {}
        for episode in self.episodes:
            for local_tick in range(EPISODE_TICKS):
                by_tick[episode.start_tick + local_tick] = (
                    episode,
                    local_tick,
                )

        spec = self.environment
        phase1 = rng.uniform(0, 2 * math.pi)
        phase2 = rng.uniform(0, 2 * math.pi)
        period1 = rng.uniform(80, 150)
        period2 = rng.uniform(31, 67)
        variance_change_tick = int(self.total_ticks * rng.uniform(0.42, 0.62))
        bias_change_tick = int(self.total_ticks * rng.uniform(0.35, 0.58))

        values = []
        ar = 0.0
        for tick in range(self.total_ticks):
            sigma = spec.base_sigma * (
                1.0
                + spec.variance_slope * max(0, tick - WARMUP_TICKS)
            )
            if tick >= variance_change_tick:
                sigma *= spec.post_variance_jump

            ar = spec.ar_phi * ar + rng.gauss(0.0, sigma)
            drift = (
                spec.drift_amp_1
                * math.sin(2 * math.pi * tick / period1 + phase1)
                + spec.drift_amp_2
                * math.sin(2 * math.pi * tick / period2 + phase2)
            )
            regime = (
                spec.regime_bias
                if tick >= bias_change_tick
                else 0.0
            )
            clean = ar + drift + regime

            post_outlier_p = (
                spec.outlier_p
                if tick >= WARMUP_TICKS
                else min(0.004, spec.outlier_p / 2)
            )
            if rng.random() < post_outlier_p:
                clean += rng.choice((-1, 1)) * rng.uniform(
                    spec.outlier_low,
                    spec.outlier_high,
                )

            attack = 0.0
            active = by_tick.get(tick)
            if active is not None:
                episode, local_tick = active
                if local_tick in episode.pulse_ticks:
                    attack = (
                        episode.direction
                        * episode.amplitude
                        * rng.uniform(0.82, 1.18)
                    )

            values.append(clean + attack)

        self.values = values

    def episode_for_tick(self, tick: int):
        for episode in self.episodes:
            if episode.start_tick <= tick < episode.end_tick:
                return episode
        return None
