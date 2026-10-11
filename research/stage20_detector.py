"""Stage 20 competitive directional evidence detectors.

Benign heavy-tailed reconciliation noise is often approximately sign-symmetric.
Stage 19 maintained positive and negative evidence independently; both could
therefore accumulate nuisance evidence without penalizing each other.

Stage 20 introduces *competitive* evidence:
- positive evidence is reduced by simultaneous/recent negative evidence;
- negative evidence is reduced by positive evidence.

A real one-direction integrity attack repeatedly reinforces one side while
symmetric clean extremes tend to cancel.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import statistics

from .stage15_detector import (
    power_betting_mixture,
    upper_tail_rank,
)
from .stage17_detector import lower_tail_rank


def robust_center_scale(
    calibration: list[float],
) -> tuple[float, float]:
    center = statistics.median(calibration)
    mad = statistics.median(
        abs(value - center) for value in calibration
    )
    return center, max(1e-6, 1.4826 * mad)


def log_e(p: float) -> float:
    return max(
        0.0,
        math.log(
            max(1e-12, power_betting_mixture(p))
        ),
    )


@dataclass(frozen=True)
class CompetitiveSparseConfig:
    windows: tuple[int, ...]
    tail_gate_p: float
    magnitude_gate_z: float
    min_hits: int
    score_threshold: float
    opposition_penalty: float
    center_alpha: float
    scale_alpha: float
    update_clip_z: float = 3.0


@dataclass(frozen=True)
class CompetitiveLeakyConfig:
    decay: float
    reference: float
    threshold: float
    tail_gate_p: float
    opposition_penalty: float
    center_alpha: float
    scale_alpha: float
    update_clip_z: float = 3.0


class _AdaptiveSignedBaseline:
    def __init__(
        self,
        calibration: list[float],
        *,
        center_alpha: float,
        scale_alpha: float,
        update_clip_z: float,
    ):
        self.center, self.scale = robust_center_scale(
            calibration
        )
        self.initial_scale = self.scale
        self.center_alpha = center_alpha
        self.scale_alpha = scale_alpha
        self.update_clip_z = update_clip_z
        self.calibration_z = [
            (value - self.center) / self.scale
            for value in calibration
        ]

    def standardize(self, value: float):
        residual = value - self.center
        z = residual / max(1e-12, self.scale)
        p_positive = upper_tail_rank(
            self.calibration_z, z
        )
        p_negative = lower_tail_rank(
            self.calibration_z, z
        )
        return residual, z, p_positive, p_negative

    def update(self, residual: float):
        cap = self.update_clip_z * self.scale
        clipped = max(-cap, min(cap, residual))
        self.center += self.center_alpha * clipped

        target_scale = 1.2533141373 * abs(clipped)
        floor = 0.45 * self.initial_scale
        ceiling = 4.0 * self.initial_scale
        target_scale = max(
            floor, min(ceiling, target_scale)
        )
        self.scale = (
            (1.0 - self.scale_alpha) * self.scale
            + self.scale_alpha * target_scale
        )
        self.scale = max(
            floor, min(ceiling, self.scale)
        )


class CompetitiveSparseDetector:
    """Rolling sparse e-evidence with opposite-sign subtraction."""

    def __init__(
        self,
        calibration: list[float],
        config: CompetitiveSparseConfig,
    ):
        self.config = config
        self.baseline = _AdaptiveSignedBaseline(
            calibration,
            center_alpha=config.center_alpha,
            scale_alpha=config.scale_alpha,
            update_clip_z=config.update_clip_z,
        )
        self.positive: list[tuple[int, float]] = []
        self.negative: list[tuple[int, float]] = []
        self.tick = -1

    def observe(self, value: float) -> tuple[bool, dict]:
        self.tick += 1
        residual, z, p_positive, p_negative = (
            self.baseline.standardize(value)
        )

        max_window = max(self.config.windows)
        outer_floor = self.tick - max_window + 1
        self.positive = [
            item for item in self.positive
            if item[0] >= outer_floor
        ]
        self.negative = [
            item for item in self.negative
            if item[0] >= outer_floor
        ]

        positive_hit = (
            z >= self.config.magnitude_gate_z
            and p_positive <= self.config.tail_gate_p
        )
        negative_hit = (
            z <= -self.config.magnitude_gate_z
            and p_negative <= self.config.tail_gate_p
        )
        if positive_hit:
            self.positive.append(
                (self.tick, log_e(p_positive))
            )
        if negative_hit:
            self.negative.append(
                (self.tick, log_e(p_negative))
            )

        positive_alarm = False
        negative_alarm = False
        best_positive = 0.0
        best_negative = 0.0
        for window in self.config.windows:
            floor = self.tick - window + 1
            pos = [
                evidence
                for hit_tick, evidence in self.positive
                if hit_tick >= floor
            ]
            neg = [
                evidence
                for hit_tick, evidence in self.negative
                if hit_tick >= floor
            ]
            pos_score = (
                sum(pos)
                - self.config.opposition_penalty * sum(neg)
            )
            neg_score = (
                sum(neg)
                - self.config.opposition_penalty * sum(pos)
            )
            best_positive = max(best_positive, pos_score)
            best_negative = max(best_negative, neg_score)
            positive_alarm = positive_alarm or (
                positive_hit
                and len(pos) >= self.config.min_hits
                and pos_score >= self.config.score_threshold
            )
            negative_alarm = negative_alarm or (
                negative_hit
                and len(neg) >= self.config.min_hits
                and neg_score >= self.config.score_threshold
            )

        alarm = positive_alarm or negative_alarm
        if alarm:
            self.positive = []
            self.negative = []

        self.baseline.update(residual)
        return alarm, {
            "robust_z": z,
            "p_positive": p_positive,
            "p_negative": p_negative,
            "positive_score": best_positive,
            "negative_score": best_negative,
        }


class CompetitiveLeakyDetector:
    """Leaky directional e-process with cross-inhibition."""

    def __init__(
        self,
        calibration: list[float],
        config: CompetitiveLeakyConfig,
    ):
        self.config = config
        self.baseline = _AdaptiveSignedBaseline(
            calibration,
            center_alpha=config.center_alpha,
            scale_alpha=config.scale_alpha,
            update_clip_z=config.update_clip_z,
        )
        self.positive = 0.0
        self.negative = 0.0

    def observe(self, value: float) -> tuple[bool, dict]:
        residual, z, p_positive, p_negative = (
            self.baseline.standardize(value)
        )
        pos_e = log_e(p_positive)
        neg_e = log_e(p_negative)

        previous_positive = self.positive
        previous_negative = self.negative
        self.positive = max(
            0.0,
            self.config.decay * previous_positive
            + pos_e
            - self.config.reference
            - self.config.opposition_penalty * neg_e,
        )
        self.negative = max(
            0.0,
            self.config.decay * previous_negative
            + neg_e
            - self.config.reference
            - self.config.opposition_penalty * pos_e,
        )

        alarm = (
            (
                self.positive >= self.config.threshold
                and p_positive <= self.config.tail_gate_p
            )
            or (
                self.negative >= self.config.threshold
                and p_negative <= self.config.tail_gate_p
            )
        )
        if alarm:
            self.positive = 0.0
            self.negative = 0.0

        self.baseline.update(residual)
        return alarm, {
            "robust_z": z,
            "p_positive": p_positive,
            "p_negative": p_negative,
            "positive_state": self.positive,
            "negative_state": self.negative,
        }


SPARSE_WINDOWS = (
    (12, 24, 48),
    (16, 32, 64),
    (20, 40, 80),
)

COMPETITIVE_SPARSE_GRID = tuple(
    CompetitiveSparseConfig(
        windows=windows,
        tail_gate_p=gate,
        magnitude_gate_z=z_gate,
        min_hits=min_hits,
        score_threshold=score,
        opposition_penalty=penalty,
        center_alpha=center_alpha,
        scale_alpha=scale_alpha,
    )
    for windows in SPARSE_WINDOWS
    for gate in (0.04, 0.07)
    for z_gate in (3.5, 4.5, 5.5)
    for min_hits in (2, 3)
    for score in (2.4, 3.2, 4.0)
    for penalty in (0.5, 1.0, 1.5)
    for center_alpha, scale_alpha in (
        (0.03, 0.02),
        (0.07, 0.04),
    )
)

COMPETITIVE_LEAKY_GRID = tuple(
    CompetitiveLeakyConfig(
        decay=decay,
        reference=reference,
        threshold=threshold,
        tail_gate_p=gate,
        opposition_penalty=penalty,
        center_alpha=center_alpha,
        scale_alpha=scale_alpha,
    )
    for decay in (0.82, 0.90, 0.96)
    for reference in (0.08, 0.15, 0.24)
    for threshold in (5.0, 7.0, 9.0)
    for gate in (0.04, 0.07, 0.10)
    for penalty in (0.5, 1.0, 1.5)
    for center_alpha, scale_alpha in (
        (0.03, 0.02),
        (0.07, 0.04),
    )
)
