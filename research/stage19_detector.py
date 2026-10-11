"""Stage 19 multiscale directional e-memory.

Stage 18 showed that a single directional memory transfers well to persistent
live tampering but completely misses sparse mutations.  Stage 19 therefore uses
a bank of leaky one-sided log-e accumulators at several time scales.

For each direction and decay lambda:
    S_t(lambda) = max(0, lambda*S_{t-1}(lambda) + log(e_t) - reference)

The scale bank is combined with log-mean-exp.  This acts as a soft maximum with
an explicit log(K) multiplicity penalty rather than simply taking the largest
state.  Fast scales respond to persistent shifts; slow scales preserve sparse
same-direction evidence across clean gaps.

The detector remains empirical under temporal dependence; no exact anytime-valid
guarantee is claimed.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

from .stage15_detector import (
    power_betting_mixture,
    upper_tail_rank,
)


def lower_tail_rank(calibration: list[float], value: float) -> float:
    return (
        1 + sum(item <= value for item in calibration)
    ) / (len(calibration) + 1)


def log_e_from_p(p: float) -> float:
    return math.log(
        max(1e-12, power_betting_mixture(p))
    )


def log_mean_exp(values: list[float]) -> float:
    if not values:
        raise ValueError("empty scale bank")
    maximum = max(values)
    return (
        maximum
        + math.log(
            sum(math.exp(value - maximum) for value in values)
            / len(values)
        )
    )


@dataclass(frozen=True)
class MultiScaleDirectionalConfig:
    decays: tuple[float, ...]
    reference: float
    threshold: float
    direction_gate_p: float


@dataclass(frozen=True)
class SingleScaleDirectionalConfig:
    decay: float
    reference: float
    threshold: float
    direction_gate_p: float


@dataclass(frozen=True)
class ScalarPageHinkleyConfig:
    delta: float
    threshold: float
    gate_p: float
    mean_alpha: float


class MultiScaleDirectionalDetector:
    def __init__(
        self,
        calibration: list[float],
        config: MultiScaleDirectionalConfig,
    ):
        self.calibration = list(calibration)
        self.config = config
        self.positive = [0.0] * len(config.decays)
        self.negative = [0.0] * len(config.decays)

    def observe(self, value: float) -> tuple[bool, dict]:
        p_positive = upper_tail_rank(
            self.calibration, value
        )
        p_negative = lower_tail_rank(
            self.calibration, value
        )
        log_positive = log_e_from_p(p_positive)
        log_negative = log_e_from_p(p_negative)

        for index, decay in enumerate(self.config.decays):
            self.positive[index] = max(
                0.0,
                decay * self.positive[index]
                + log_positive
                - self.config.reference,
            )
            self.negative[index] = max(
                0.0,
                decay * self.negative[index]
                + log_negative
                - self.config.reference,
            )

        positive_score = log_mean_exp(self.positive)
        negative_score = log_mean_exp(self.negative)

        alarm = (
            (
                positive_score >= self.config.threshold
                and p_positive <= self.config.direction_gate_p
            )
            or (
                negative_score >= self.config.threshold
                and p_negative <= self.config.direction_gate_p
            )
        )
        if alarm:
            self.positive = [0.0] * len(self.config.decays)
            self.negative = [0.0] * len(self.config.decays)

        return alarm, {
            "p_positive": p_positive,
            "p_negative": p_negative,
            "positive_score": positive_score,
            "negative_score": negative_score,
        }


class SingleScaleDirectionalDetector:
    def __init__(
        self,
        calibration: list[float],
        config: SingleScaleDirectionalConfig,
    ):
        self.calibration = list(calibration)
        self.config = config
        self.positive = 0.0
        self.negative = 0.0

    def observe(self, value: float) -> tuple[bool, dict]:
        p_positive = upper_tail_rank(
            self.calibration, value
        )
        p_negative = lower_tail_rank(
            self.calibration, value
        )
        self.positive = max(
            0.0,
            self.config.decay * self.positive
            + log_e_from_p(p_positive)
            - self.config.reference,
        )
        self.negative = max(
            0.0,
            self.config.decay * self.negative
            + log_e_from_p(p_negative)
            - self.config.reference,
        )
        alarm = (
            (
                self.positive >= self.config.threshold
                and p_positive <= self.config.direction_gate_p
            )
            or (
                self.negative >= self.config.threshold
                and p_negative <= self.config.direction_gate_p
            )
        )
        if alarm:
            self.positive = 0.0
            self.negative = 0.0
        return alarm, {
            "p_positive": p_positive,
            "p_negative": p_negative,
            "positive_score": self.positive,
            "negative_score": self.negative,
        }


class ScalarPageHinkleyDetector:
    def __init__(
        self,
        absolute_calibration: list[float],
        config: ScalarPageHinkleyConfig,
    ):
        self.calibration = list(absolute_calibration)
        self.config = config
        self.mean = 1.0
        self.cumulative = 0.0
        self.minimum = 0.0

    def observe(self, value: float) -> tuple[bool, dict]:
        absolute = abs(value)
        p = upper_tail_rank(
            self.calibration, absolute
        )
        surprise = -math.log(max(1e-12, p))
        self.mean = (
            (1.0 - self.config.mean_alpha) * self.mean
            + self.config.mean_alpha * surprise
        )
        self.cumulative += (
            surprise - self.mean - self.config.delta
        )
        self.minimum = min(
            self.minimum, self.cumulative
        )
        statistic = self.cumulative - self.minimum
        alarm = (
            statistic >= self.config.threshold
            and p <= self.config.gate_p
        )
        if alarm:
            self.cumulative = 0.0
            self.minimum = 0.0
        return alarm, {
            "p_absolute": p,
            "statistic": statistic,
        }


MULTISCALE_BANKS = (
    (0.60, 0.85, 0.97),
    (0.75, 0.93, 0.99),
    (0.85, 0.97, 0.995),
    (0.70, 0.90, 0.98, 0.997),
)

MULTISCALE_GRID = tuple(
    MultiScaleDirectionalConfig(
        decays=bank,
        reference=reference,
        threshold=threshold,
        direction_gate_p=gate,
    )
    for bank in MULTISCALE_BANKS
    for reference in (0.02, 0.06, 0.12)
    for threshold in (2.4, 3.2, 4.2, 5.4, 7.0)
    for gate in (0.04, 0.07, 0.10)
)

SINGLE_SCALE_GRID = tuple(
    SingleScaleDirectionalConfig(
        decay=decay,
        reference=reference,
        threshold=threshold,
        direction_gate_p=gate,
    )
    for decay in (0.85, 0.90, 0.96, 0.99)
    for reference in (0.02, 0.06, 0.12)
    for threshold in (2.4, 3.2, 4.2, 5.4, 7.0)
    for gate in (0.04, 0.07, 0.10)
)

PAGE_HINKLEY_GRID = tuple(
    ScalarPageHinkleyConfig(
        delta=delta,
        threshold=threshold,
        gate_p=gate,
        mean_alpha=alpha,
    )
    for delta in (0.30, 0.50, 0.70)
    for threshold in (5.0, 7.0, 9.0, 12.0)
    for gate in (0.04, 0.08, 0.12)
    for alpha in (0.05, 0.10, 0.20)
)
