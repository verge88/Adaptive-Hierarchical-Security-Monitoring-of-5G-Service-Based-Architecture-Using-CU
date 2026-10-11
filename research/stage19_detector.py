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
import statistics

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


@dataclass(frozen=True)
class SparseEScanConfig:
    """Multi-window directional scan over extreme one-sided e-evidence."""

    windows: tuple[int, ...]
    tail_gate_p: float
    min_hits: int
    e_sum_threshold: float


class SparseEScanDetector:
    """Detect repeated sparse directional tail evidence in rolling windows.

    Only observations whose one-sided p-value passes the tail gate enter the
    evidence buffer. An alarm requires multiple same-direction tail hits in at
    least one declared window and sufficient summed positive log-evidence.
    Single clean outliers therefore cannot alarm by themselves.

    Multiple windows make the detector insensitive to one assumed pulse gap:
    short windows react quickly to dense attacks while long windows retain
    sparse evidence.
    """

    def __init__(
        self,
        calibration: list[float],
        config: SparseEScanConfig,
    ):
        self.calibration = list(calibration)
        self.config = config
        self.positive_hits: list[tuple[int, float]] = []
        self.negative_hits: list[tuple[int, float]] = []
        self.tick = -1

    def _scan(
        self,
        hits: list[tuple[int, float]],
    ) -> tuple[bool, dict]:
        stats = {}
        alarm = False
        for window in self.config.windows:
            floor = self.tick - window + 1
            values = [
                value
                for tick, value in hits
                if tick >= floor
            ]
            total = sum(values)
            stats[str(window)] = {
                "hits": len(values),
                "log_e_sum": total,
            }
            if (
                len(values) >= self.config.min_hits
                and total >= self.config.e_sum_threshold
            ):
                alarm = True
        return alarm, stats

    def observe(self, value: float) -> tuple[bool, dict]:
        self.tick += 1
        p_positive = upper_tail_rank(
            self.calibration, value
        )
        p_negative = lower_tail_rank(
            self.calibration, value
        )

        max_window = max(self.config.windows)
        floor = self.tick - max_window + 1
        self.positive_hits = [
            item for item in self.positive_hits if item[0] >= floor
        ]
        self.negative_hits = [
            item for item in self.negative_hits if item[0] >= floor
        ]

        if p_positive <= self.config.tail_gate_p:
            self.positive_hits.append(
                (self.tick, max(0.0, log_e_from_p(p_positive)))
            )
        if p_negative <= self.config.tail_gate_p:
            self.negative_hits.append(
                (self.tick, max(0.0, log_e_from_p(p_negative)))
            )

        positive_alarm, positive_stats = self._scan(
            self.positive_hits
        )
        negative_alarm, negative_stats = self._scan(
            self.negative_hits
        )

        current_tail = (
            p_positive <= self.config.tail_gate_p
            or p_negative <= self.config.tail_gate_p
        )
        alarm = current_tail and (
            positive_alarm or negative_alarm
        )
        if alarm:
            self.positive_hits = []
            self.negative_hits = []

        return alarm, {
            "p_positive": p_positive,
            "p_negative": p_negative,
            "positive_windows": positive_stats,
            "negative_windows": negative_stats,
        }


SPARSE_SCAN_BANKS = (
    (8, 16, 32),
    (12, 24, 48),
    (8, 20, 40),
    (16, 32, 64),
)

SPARSE_SCAN_GRID = tuple(
    SparseEScanConfig(
        windows=windows,
        tail_gate_p=gate,
        min_hits=min_hits,
        e_sum_threshold=threshold,
    )
    for windows in SPARSE_SCAN_BANKS
    for gate in (0.04, 0.07, 0.10)
    for min_hits in (2, 3)
    for threshold in (1.2, 1.6, 2.0, 2.6, 3.2)
)

SINGLE_WINDOW_SCAN_GRID = tuple(
    SparseEScanConfig(
        windows=(window,),
        tail_gate_p=gate,
        min_hits=min_hits,
        e_sum_threshold=threshold,
    )
    for window in (12, 18, 24, 36)
    for gate in (0.04, 0.07, 0.10)
    for min_hits in (2, 3)
    for threshold in (1.2, 1.6, 2.0, 2.6, 3.2)
)


def robust_center_scale(calibration: list[float]) -> tuple[float, float]:
    center = statistics.median(calibration)
    mad = statistics.median(
        abs(value - center) for value in calibration
    )
    return center, max(1e-6, 1.4826 * mad)


@dataclass(frozen=True)
class RobustSparseEScanConfig:
    """Sparse directional scan with independent robust-amplitude gate."""

    windows: tuple[int, ...]
    tail_gate_p: float
    magnitude_gate_z: float
    min_hits: int
    e_sum_threshold: float


class RobustSparseEScanDetector:
    """Multi-window e-scan requiring both rank-tail and MAD-scale evidence."""

    def __init__(
        self,
        calibration: list[float],
        config: RobustSparseEScanConfig,
    ):
        self.calibration = list(calibration)
        self.config = config
        self.center, self.scale = robust_center_scale(
            calibration
        )
        self.positive_hits: list[tuple[int, float]] = []
        self.negative_hits: list[tuple[int, float]] = []
        self.tick = -1

    def observe(self, value: float) -> tuple[bool, dict]:
        self.tick += 1
        p_positive = upper_tail_rank(
            self.calibration, value
        )
        p_negative = lower_tail_rank(
            self.calibration, value
        )
        z = (value - self.center) / self.scale

        max_window = max(self.config.windows)
        floor = self.tick - max_window + 1
        self.positive_hits = [
            item for item in self.positive_hits if item[0] >= floor
        ]
        self.negative_hits = [
            item for item in self.negative_hits if item[0] >= floor
        ]

        positive_hit = (
            p_positive <= self.config.tail_gate_p
            and z >= self.config.magnitude_gate_z
        )
        negative_hit = (
            p_negative <= self.config.tail_gate_p
            and z <= -self.config.magnitude_gate_z
        )
        if positive_hit:
            self.positive_hits.append(
                (self.tick, max(0.0, log_e_from_p(p_positive)))
            )
        if negative_hit:
            self.negative_hits.append(
                (self.tick, max(0.0, log_e_from_p(p_negative)))
            )

        positive_alarm = False
        negative_alarm = False
        diagnostics = {}
        for direction, hits in (
            ("positive", self.positive_hits),
            ("negative", self.negative_hits),
        ):
            direction_stats = {}
            for window in self.config.windows:
                window_floor = self.tick - window + 1
                values = [
                    evidence
                    for hit_tick, evidence in hits
                    if hit_tick >= window_floor
                ]
                direction_stats[str(window)] = {
                    "hits": len(values),
                    "log_e_sum": sum(values),
                }
                passed = (
                    len(values) >= self.config.min_hits
                    and sum(values)
                    >= self.config.e_sum_threshold
                )
                if direction == "positive":
                    positive_alarm = positive_alarm or passed
                else:
                    negative_alarm = negative_alarm or passed
            diagnostics[direction] = direction_stats

        current_hit = positive_hit or negative_hit
        alarm = current_hit and (
            positive_alarm or negative_alarm
        )
        if alarm:
            self.positive_hits = []
            self.negative_hits = []

        return alarm, {
            "p_positive": p_positive,
            "p_negative": p_negative,
            "robust_z": z,
            "windows": diagnostics,
        }


ROBUST_SPARSE_SCAN_GRID = tuple(
    RobustSparseEScanConfig(
        windows=windows,
        tail_gate_p=gate,
        magnitude_gate_z=z_gate,
        min_hits=min_hits,
        e_sum_threshold=threshold,
    )
    for windows in SPARSE_SCAN_BANKS
    for gate in (0.04, 0.07)
    for z_gate in (3.0, 4.0, 5.0)
    for min_hits in (2, 3)
    for threshold in (1.6, 2.2, 2.8, 3.4)
)

ROBUST_SINGLE_WINDOW_SCAN_GRID = tuple(
    RobustSparseEScanConfig(
        windows=(window,),
        tail_gate_p=gate,
        magnitude_gate_z=z_gate,
        min_hits=min_hits,
        e_sum_threshold=threshold,
    )
    for window in (12, 18, 24, 36)
    for gate in (0.04, 0.07)
    for z_gate in (3.0, 4.0, 5.0)
    for min_hits in (2, 3)
    for threshold in (1.6, 2.2, 2.8, 3.4)
)


@dataclass(frozen=True)
class AdaptiveRobustSparseEScanConfig:
    """Sparse e-scan with clipped online robust location/scale adaptation."""

    windows: tuple[int, ...]
    tail_gate_p: float
    magnitude_gate_z: float
    min_hits: int
    e_sum_threshold: float
    center_alpha: float
    scale_alpha: float
    update_clip_z: float = 3.0


class AdaptiveRobustSparseEScanDetector:
    """Sparse directional scan on adaptively standardized signed residuals."""

    def __init__(
        self,
        calibration: list[float],
        config: AdaptiveRobustSparseEScanConfig,
    ):
        self.config = config
        self.center, self.scale = robust_center_scale(
            calibration
        )
        self.initial_scale = self.scale
        self.calibration_z = [
            (value - self.center) / self.scale
            for value in calibration
        ]
        self.positive_hits: list[tuple[int, float]] = []
        self.negative_hits: list[tuple[int, float]] = []
        self.tick = -1

    def _update_baseline(self, residual: float):
        cap = self.config.update_clip_z * self.scale
        clipped = max(-cap, min(cap, residual))
        self.center += self.config.center_alpha * clipped

        # For a centered Gaussian, E|X| = sigma*sqrt(2/pi).
        target_scale = 1.2533141373 * abs(clipped)
        floor = 0.45 * self.initial_scale
        ceiling = 4.0 * self.initial_scale
        target_scale = max(
            floor, min(ceiling, target_scale)
        )
        self.scale = (
            (1.0 - self.config.scale_alpha) * self.scale
            + self.config.scale_alpha * target_scale
        )
        self.scale = max(floor, min(ceiling, self.scale))

    def observe(self, value: float) -> tuple[bool, dict]:
        self.tick += 1
        residual = value - self.center
        z = residual / max(1e-12, self.scale)
        p_positive = upper_tail_rank(
            self.calibration_z, z
        )
        p_negative = lower_tail_rank(
            self.calibration_z, z
        )

        max_window = max(self.config.windows)
        floor = self.tick - max_window + 1
        self.positive_hits = [
            item for item in self.positive_hits if item[0] >= floor
        ]
        self.negative_hits = [
            item for item in self.negative_hits if item[0] >= floor
        ]

        positive_hit = (
            p_positive <= self.config.tail_gate_p
            and z >= self.config.magnitude_gate_z
        )
        negative_hit = (
            p_negative <= self.config.tail_gate_p
            and z <= -self.config.magnitude_gate_z
        )
        if positive_hit:
            self.positive_hits.append(
                (self.tick, max(0.0, log_e_from_p(p_positive)))
            )
        if negative_hit:
            self.negative_hits.append(
                (self.tick, max(0.0, log_e_from_p(p_negative)))
            )

        positive_alarm = False
        negative_alarm = False
        for hits, direction in (
            (self.positive_hits, "positive"),
            (self.negative_hits, "negative"),
        ):
            passed = False
            for window in self.config.windows:
                window_floor = self.tick - window + 1
                values = [
                    evidence
                    for hit_tick, evidence in hits
                    if hit_tick >= window_floor
                ]
                passed = passed or (
                    len(values) >= self.config.min_hits
                    and sum(values)
                    >= self.config.e_sum_threshold
                )
            if direction == "positive":
                positive_alarm = passed
            else:
                negative_alarm = passed

        alarm = (
            (positive_hit or negative_hit)
            and (positive_alarm or negative_alarm)
        )
        if alarm:
            self.positive_hits = []
            self.negative_hits = []

        # Adapt after scoring. Clipping limits attack contamination.
        self._update_baseline(residual)

        return alarm, {
            "p_positive": p_positive,
            "p_negative": p_negative,
            "robust_z": z,
            "center": self.center,
            "scale": self.scale,
        }


ADAPTATION_PAIRS = (
    (0.03, 0.02),
    (0.08, 0.04),
    (0.15, 0.06),
)

ADAPTIVE_ROBUST_SCAN_GRID = tuple(
    AdaptiveRobustSparseEScanConfig(
        windows=windows,
        tail_gate_p=gate,
        magnitude_gate_z=z_gate,
        min_hits=min_hits,
        e_sum_threshold=threshold,
        center_alpha=center_alpha,
        scale_alpha=scale_alpha,
    )
    for windows in SPARSE_SCAN_BANKS
    for gate in (0.04, 0.07)
    for z_gate in (3.5, 4.5)
    for min_hits in (2, 3)
    for threshold in (2.2, 2.8, 3.4)
    for center_alpha, scale_alpha in ADAPTATION_PAIRS
)

ADAPTIVE_ROBUST_SINGLE_WINDOW_GRID = tuple(
    AdaptiveRobustSparseEScanConfig(
        windows=(window,),
        tail_gate_p=gate,
        magnitude_gate_z=z_gate,
        min_hits=min_hits,
        e_sum_threshold=threshold,
        center_alpha=center_alpha,
        scale_alpha=scale_alpha,
    )
    for window in (12, 18, 24, 36)
    for gate in (0.04, 0.07)
    for z_gate in (3.5, 4.5)
    for min_hits in (2, 3)
    for threshold in (2.2, 2.8, 3.4)
    for center_alpha, scale_alpha in ADAPTATION_PAIRS
)


@dataclass(frozen=True)
class DualPathDirectionalConfig:
    """Adaptive sparse path plus short-window sustained-direction path."""

    sparse_windows: tuple[int, ...]
    sparse_tail_gate_p: float
    sparse_magnitude_gate_z: float
    sparse_min_hits: int
    sparse_e_sum_threshold: float
    center_alpha: float
    scale_alpha: float
    sustained_window: int
    sustained_hits: int
    sustained_z: float
    sustained_gate_p: float
    update_clip_z: float = 3.0


class DualPathDirectionalDetector:
    """Combine sparse extreme evidence with sustained moderate evidence.

    The sparse path is the adaptive robust multi-window e-scan. The sustained
    path detects several moderate same-direction residuals in a short window.
    Both paths share the same clipped online location/scale baseline.
    """

    def __init__(
        self,
        calibration: list[float],
        config: DualPathDirectionalConfig,
    ):
        self.config = config
        self.center, self.scale = robust_center_scale(calibration)
        self.initial_scale = self.scale
        self.calibration_z = [
            (value - self.center) / self.scale
            for value in calibration
        ]
        self.sparse_positive: list[tuple[int, float]] = []
        self.sparse_negative: list[tuple[int, float]] = []
        self.sustained_positive: list[int] = []
        self.sustained_negative: list[int] = []
        self.tick = -1

    def _update_baseline(self, residual: float):
        cap = self.config.update_clip_z * self.scale
        clipped = max(-cap, min(cap, residual))
        self.center += self.config.center_alpha * clipped
        target_scale = 1.2533141373 * abs(clipped)
        floor = 0.45 * self.initial_scale
        ceiling = 4.0 * self.initial_scale
        target_scale = max(floor, min(ceiling, target_scale))
        self.scale = (
            (1.0 - self.config.scale_alpha) * self.scale
            + self.config.scale_alpha * target_scale
        )
        self.scale = max(floor, min(ceiling, self.scale))

    def observe(self, value: float) -> tuple[bool, dict]:
        self.tick += 1
        residual = value - self.center
        z = residual / max(1e-12, self.scale)
        p_positive = upper_tail_rank(self.calibration_z, z)
        p_negative = lower_tail_rank(self.calibration_z, z)

        max_sparse_window = max(self.config.sparse_windows)
        sparse_floor = self.tick - max_sparse_window + 1
        self.sparse_positive = [
            item for item in self.sparse_positive
            if item[0] >= sparse_floor
        ]
        self.sparse_negative = [
            item for item in self.sparse_negative
            if item[0] >= sparse_floor
        ]

        sparse_positive_hit = (
            p_positive <= self.config.sparse_tail_gate_p
            and z >= self.config.sparse_magnitude_gate_z
        )
        sparse_negative_hit = (
            p_negative <= self.config.sparse_tail_gate_p
            and z <= -self.config.sparse_magnitude_gate_z
        )
        if sparse_positive_hit:
            self.sparse_positive.append(
                (self.tick, max(0.0, log_e_from_p(p_positive)))
            )
        if sparse_negative_hit:
            self.sparse_negative.append(
                (self.tick, max(0.0, log_e_from_p(p_negative)))
            )

        sparse_positive_alarm = False
        sparse_negative_alarm = False
        for window in self.config.sparse_windows:
            floor = self.tick - window + 1
            pos = [
                evidence for hit_tick, evidence in self.sparse_positive
                if hit_tick >= floor
            ]
            neg = [
                evidence for hit_tick, evidence in self.sparse_negative
                if hit_tick >= floor
            ]
            sparse_positive_alarm = sparse_positive_alarm or (
                len(pos) >= self.config.sparse_min_hits
                and sum(pos) >= self.config.sparse_e_sum_threshold
            )
            sparse_negative_alarm = sparse_negative_alarm or (
                len(neg) >= self.config.sparse_min_hits
                and sum(neg) >= self.config.sparse_e_sum_threshold
            )

        sustained_floor = self.tick - self.config.sustained_window + 1
        self.sustained_positive = [
            tick for tick in self.sustained_positive
            if tick >= sustained_floor
        ]
        self.sustained_negative = [
            tick for tick in self.sustained_negative
            if tick >= sustained_floor
        ]
        sustained_positive_hit = (
            z >= self.config.sustained_z
            and p_positive <= self.config.sustained_gate_p
        )
        sustained_negative_hit = (
            z <= -self.config.sustained_z
            and p_negative <= self.config.sustained_gate_p
        )
        if sustained_positive_hit:
            self.sustained_positive.append(self.tick)
        if sustained_negative_hit:
            self.sustained_negative.append(self.tick)

        sparse_alarm = (
            (
                sparse_positive_hit and sparse_positive_alarm
            )
            or (
                sparse_negative_hit and sparse_negative_alarm
            )
        )
        sustained_alarm = (
            (
                sustained_positive_hit
                and len(self.sustained_positive)
                >= self.config.sustained_hits
            )
            or (
                sustained_negative_hit
                and len(self.sustained_negative)
                >= self.config.sustained_hits
            )
        )
        alarm = sparse_alarm or sustained_alarm

        if alarm:
            self.sparse_positive = []
            self.sparse_negative = []
            self.sustained_positive = []
            self.sustained_negative = []

        self._update_baseline(residual)

        return alarm, {
            "p_positive": p_positive,
            "p_negative": p_negative,
            "robust_z": z,
            "sparse_alarm": sparse_alarm,
            "sustained_alarm": sustained_alarm,
        }


DUAL_SPARSE_BASES = (
    ((16, 32, 64), 0.07, 3.5, 2, 2.2),
    ((16, 32, 64), 0.04, 3.5, 2, 2.2),
    ((16, 32, 64), 0.07, 4.5, 2, 2.2),
    ((16, 32, 64), 0.04, 4.5, 2, 2.2),
    ((12, 24, 48), 0.07, 3.5, 2, 2.2),
    ((8, 20, 40), 0.07, 3.5, 2, 2.2),
    ((16, 32, 64), 0.07, 3.5, 3, 2.8),
    ((16, 32, 64), 0.04, 3.5, 3, 2.8),
)

SUSTAINED_PATTERNS = (
    (4, 3),
    (5, 3),
    (6, 4),
    (8, 5),
)

DUAL_PATH_GRID = tuple(
    DualPathDirectionalConfig(
        sparse_windows=windows,
        sparse_tail_gate_p=tail_gate,
        sparse_magnitude_gate_z=z_gate,
        sparse_min_hits=min_hits,
        sparse_e_sum_threshold=e_threshold,
        center_alpha=0.03,
        scale_alpha=0.02,
        sustained_window=sustained_window,
        sustained_hits=sustained_hits,
        sustained_z=sustained_z,
        sustained_gate_p=sustained_gate,
    )
    for (
        windows,
        tail_gate,
        z_gate,
        min_hits,
        e_threshold,
    ) in DUAL_SPARSE_BASES
    for sustained_window, sustained_hits in SUSTAINED_PATTERNS
    for sustained_z in (1.8, 2.2, 2.6, 3.0)
    for sustained_gate in (0.15, 0.25)
)


@dataclass(frozen=True)
class SparsePlusDirectionalConfig:
    """Independent adaptive sparse path plus raw directional e-process."""

    sparse_windows: tuple[int, ...]
    sparse_tail_gate_p: float
    sparse_magnitude_gate_z: float
    sparse_min_hits: int
    sparse_e_sum_threshold: float
    center_alpha: float
    scale_alpha: float
    single_decay: float
    single_reference: float
    single_threshold: float
    single_gate_p: float
    update_clip_z: float = 3.0


class SparsePlusDirectionalDetector:
    """OR-fusion of sparse adaptive scan and persistent raw e-process."""

    def __init__(
        self,
        calibration: list[float],
        config: SparsePlusDirectionalConfig,
    ):
        self.config = config
        self.raw_calibration = list(calibration)
        self.center, self.scale = robust_center_scale(calibration)
        self.initial_scale = self.scale
        self.calibration_z = [
            (value - self.center) / self.scale
            for value in calibration
        ]
        self.sparse_positive: list[tuple[int, float]] = []
        self.sparse_negative: list[tuple[int, float]] = []
        self.single_positive = 0.0
        self.single_negative = 0.0
        self.tick = -1

    def _update_baseline(self, residual: float):
        cap = self.config.update_clip_z * self.scale
        clipped = max(-cap, min(cap, residual))
        self.center += self.config.center_alpha * clipped
        target_scale = 1.2533141373 * abs(clipped)
        floor = 0.45 * self.initial_scale
        ceiling = 4.0 * self.initial_scale
        target_scale = max(floor, min(ceiling, target_scale))
        self.scale = (
            (1.0 - self.config.scale_alpha) * self.scale
            + self.config.scale_alpha * target_scale
        )
        self.scale = max(floor, min(ceiling, self.scale))

    def observe(self, value: float) -> tuple[bool, dict]:
        self.tick += 1

        # Persistent channel: exactly the raw signed-rank recurrence family.
        raw_p_positive = upper_tail_rank(
            self.raw_calibration, value
        )
        raw_p_negative = lower_tail_rank(
            self.raw_calibration, value
        )
        self.single_positive = max(
            0.0,
            self.config.single_decay * self.single_positive
            + log_e_from_p(raw_p_positive)
            - self.config.single_reference,
        )
        self.single_negative = max(
            0.0,
            self.config.single_decay * self.single_negative
            + log_e_from_p(raw_p_negative)
            - self.config.single_reference,
        )
        persistent_alarm = (
            (
                self.single_positive >= self.config.single_threshold
                and raw_p_positive <= self.config.single_gate_p
            )
            or (
                self.single_negative >= self.config.single_threshold
                and raw_p_negative <= self.config.single_gate_p
            )
        )

        # Sparse channel: adaptively standardized extreme-hit scan.
        residual = value - self.center
        z = residual / max(1e-12, self.scale)
        p_positive = upper_tail_rank(
            self.calibration_z, z
        )
        p_negative = lower_tail_rank(
            self.calibration_z, z
        )

        max_window = max(self.config.sparse_windows)
        floor = self.tick - max_window + 1
        self.sparse_positive = [
            item for item in self.sparse_positive if item[0] >= floor
        ]
        self.sparse_negative = [
            item for item in self.sparse_negative if item[0] >= floor
        ]

        positive_hit = (
            p_positive <= self.config.sparse_tail_gate_p
            and z >= self.config.sparse_magnitude_gate_z
        )
        negative_hit = (
            p_negative <= self.config.sparse_tail_gate_p
            and z <= -self.config.sparse_magnitude_gate_z
        )
        if positive_hit:
            self.sparse_positive.append(
                (self.tick, max(0.0, log_e_from_p(p_positive)))
            )
        if negative_hit:
            self.sparse_negative.append(
                (self.tick, max(0.0, log_e_from_p(p_negative)))
            )

        sparse_positive_alarm = False
        sparse_negative_alarm = False
        for window in self.config.sparse_windows:
            window_floor = self.tick - window + 1
            pos = [
                evidence for hit_tick, evidence in self.sparse_positive
                if hit_tick >= window_floor
            ]
            neg = [
                evidence for hit_tick, evidence in self.sparse_negative
                if hit_tick >= window_floor
            ]
            sparse_positive_alarm = sparse_positive_alarm or (
                len(pos) >= self.config.sparse_min_hits
                and sum(pos) >= self.config.sparse_e_sum_threshold
            )
            sparse_negative_alarm = sparse_negative_alarm or (
                len(neg) >= self.config.sparse_min_hits
                and sum(neg) >= self.config.sparse_e_sum_threshold
            )
        sparse_alarm = (
            positive_hit and sparse_positive_alarm
        ) or (
            negative_hit and sparse_negative_alarm
        )

        alarm = persistent_alarm or sparse_alarm
        if alarm:
            self.single_positive = 0.0
            self.single_negative = 0.0
            self.sparse_positive = []
            self.sparse_negative = []

        self._update_baseline(residual)

        return alarm, {
            "persistent_alarm": persistent_alarm,
            "sparse_alarm": sparse_alarm,
            "raw_p_positive": raw_p_positive,
            "raw_p_negative": raw_p_negative,
            "robust_z": z,
        }


SPARSE_PLUS_BASES = (
    ((16, 32, 64), 0.07, 3.5, 2, 2.2),
    ((16, 32, 64), 0.04, 3.5, 2, 2.2),
    ((16, 32, 64), 0.07, 4.5, 2, 2.2),
    ((16, 32, 64), 0.07, 3.5, 3, 2.8),
)

SPARSE_PLUS_DIRECTIONAL_GRID = tuple(
    SparsePlusDirectionalConfig(
        sparse_windows=windows,
        sparse_tail_gate_p=tail_gate,
        sparse_magnitude_gate_z=z_gate,
        sparse_min_hits=min_hits,
        sparse_e_sum_threshold=e_threshold,
        center_alpha=0.03,
        scale_alpha=0.02,
        single_decay=decay,
        single_reference=reference,
        single_threshold=threshold,
        single_gate_p=single_gate,
    )
    for (
        windows,
        tail_gate,
        z_gate,
        min_hits,
        e_threshold,
    ) in SPARSE_PLUS_BASES
    for decay in (0.85, 0.90, 0.96, 0.99)
    for reference in (0.06, 0.12, 0.18, 0.25)
    for threshold in (7.0, 9.0, 11.0)
    for single_gate in (0.04, 0.07)
)


@dataclass(frozen=True)
class RawSustainedConfig:
    """Short-window same-direction moderate-residual detector."""

    window: int
    hits: int
    magnitude_gate_z: float
    tail_gate_p: float


class RawSustainedDirectionalDetector:
    """Detect persistent signed shifts using fixed warm-up robust scale."""

    def __init__(
        self,
        calibration: list[float],
        config: RawSustainedConfig,
    ):
        self.config = config
        self.center, self.scale = robust_center_scale(calibration)
        self.calibration_z = [
            (value - self.center) / self.scale
            for value in calibration
        ]
        self.positive_hits: list[int] = []
        self.negative_hits: list[int] = []
        self.tick = -1

    def observe(self, value: float) -> tuple[bool, dict]:
        self.tick += 1
        z = (value - self.center) / self.scale
        p_positive = upper_tail_rank(self.calibration_z, z)
        p_negative = lower_tail_rank(self.calibration_z, z)

        floor = self.tick - self.config.window + 1
        self.positive_hits = [
            tick for tick in self.positive_hits if tick >= floor
        ]
        self.negative_hits = [
            tick for tick in self.negative_hits if tick >= floor
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
            self.positive_hits.append(self.tick)
            # Opposite-direction accumulation cannot survive a strong hit.
            self.negative_hits = []
        elif negative_hit:
            self.negative_hits.append(self.tick)
            self.positive_hits = []

        alarm = (
            positive_hit
            and len(self.positive_hits) >= self.config.hits
        ) or (
            negative_hit
            and len(self.negative_hits) >= self.config.hits
        )
        if alarm:
            self.positive_hits = []
            self.negative_hits = []

        return alarm, {
            "robust_z": z,
            "p_positive": p_positive,
            "p_negative": p_negative,
        }


RAW_SUSTAINED_GRID = tuple(
    RawSustainedConfig(
        window=window,
        hits=hits,
        magnitude_gate_z=z_gate,
        tail_gate_p=p_gate,
    )
    for window, hits in (
        (4, 3),
        (5, 4),
        (6, 4),
        (8, 5),
        (10, 6),
        (12, 7),
    )
    for z_gate in (1.2, 1.5, 1.8, 2.2, 2.6)
    for p_gate in (0.15, 0.25, 0.35)
)
