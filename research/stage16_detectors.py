"""Strong Stage-16 sequential baselines with reproducible tuning grids.

All classic baselines use the same warm-up observations, the same hierarchical
features and the same fixed CU schedule as the frozen Stage-15 e-CUSUM.  This
avoids giving the new detector a feature-engineering advantage.

Only the detector *recurrence* differs:
- calibrated_static: one-shot calibrated surprise threshold;
- ewma: exponentially weighted sequential surprise;
- cusum: Page-style positive CUSUM;
- page_hinkley: running-mean Page-Hinkley statistic.

Their hyperparameters are selected automatically on Stage-16 tuning seeds by
research.stage16_tune and are never fit on the evaluation seed block.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

from .stage15_detector import discrepancy, upper_tail_rank
from .stage15_simulation import (
    CHALLENGES_PER_TICK,
    N_NF,
    STEP_SECONDS,
    WARMUP,
    PassiveRisk,
)
from .stage16_simulation import fixed_schedule


@dataclass(frozen=True)
class StaticCalibratedConfig:
    threshold: float
    integrity_gate_p: float


@dataclass(frozen=True)
class EWMAConfig:
    alpha: float
    threshold: float
    integrity_gate_p: float


@dataclass(frozen=True)
class CUSUMConfig:
    reference: float
    threshold: float
    integrity_gate_p: float


@dataclass(frozen=True)
class PageHinkleyConfig:
    delta: float
    threshold: float
    integrity_gate_p: float
    mean_alpha: float


STATIC_GRID = tuple(
    StaticCalibratedConfig(threshold=h, integrity_gate_p=g)
    for h in (3.3, 3.8, 4.3, 4.8, 5.3)
    for g in (0.02, 0.04, 0.07, 0.10)
)

EWMA_GRID = tuple(
    EWMAConfig(alpha=a, threshold=h, integrity_gate_p=g)
    for a in (0.22, 0.35, 0.50)
    for h in (2.0, 2.5, 3.0, 3.5, 4.0)
    for g in (0.03, 0.06, 0.10)
)

CUSUM_GRID = tuple(
    CUSUMConfig(reference=k, threshold=h, integrity_gate_p=g)
    for k in (0.65, 0.90, 1.15, 1.40)
    for h in (4.0, 6.0, 8.0, 11.0, 14.0)
    for g in (0.03, 0.06, 0.10)
)

PAGE_HINKLEY_GRID = tuple(
    PageHinkleyConfig(
        delta=d,
        threshold=h,
        integrity_gate_p=g,
        mean_alpha=a,
    )
    for d in (0.15, 0.30, 0.50)
    for h in (3.5, 5.0, 7.0, 9.5, 12.0)
    for g in (0.03, 0.06, 0.10)
    for a in (0.03, 0.07)
)


class CalibratedSurprise:
    """Shared OOD feature calibration for all classic baselines."""

    joint_weight = 0.30
    joint_risk_weight = 0.16
    joint_processing_weight = 0.05

    def __init__(self, world):
        self.risk = PassiveRisk(world)
        calibration_risk = PassiveRisk(world)
        self.integrity_calibration: list[float] = []
        self.joint_calibration: list[float] = []

        for tick, row in enumerate(
            world.samples[: WARMUP // STEP_SECONDS]
        ):
            hierarchical = calibration_risk.risks(row)
            for nf in fixed_schedule(tick):
                sample = row[nf]
                d = discrepancy(sample)
                joint = self._joint_score(
                    calibration_risk,
                    nf,
                    sample,
                    hierarchical[nf],
                    d,
                )
                self.integrity_calibration.append(d)
                self.joint_calibration.append(joint)

        expected = (
            WARMUP // STEP_SECONDS
        ) * CHALLENGES_PER_TICK
        if len(self.integrity_calibration) != expected:
            raise AssertionError(
                "Unexpected Stage16 calibration budget"
            )

    def _joint_score(
        self,
        risk_model: PassiveRisk,
        nf: int,
        sample,
        hierarchical_risk: float,
        d: float,
    ) -> float:
        processing_z = risk_model.processing_z(nf, sample)
        return d * (
            1.0
            + self.joint_risk_weight
            * min(6.0, hierarchical_risk)
            + self.joint_processing_weight
            * min(6.0, processing_z)
        )

    def evidence_features(
        self,
        nf: int,
        sample,
        hierarchical_risk: float,
    ) -> tuple[float, float, float]:
        d = discrepancy(sample)
        joint = self._joint_score(
            self.risk,
            nf,
            sample,
            hierarchical_risk,
            d,
        )
        p_integrity = upper_tail_rank(
            self.integrity_calibration, d
        )
        p_joint = upper_tail_rank(
            self.joint_calibration, joint
        )
        # Surprise is bounded by finite warm-up rank resolution, making the
        # sequential baselines numerically stable.
        s_integrity = -math.log(max(p_integrity, 1e-12))
        s_joint = -math.log(max(p_joint, 1e-12))
        surprise = (
            (1.0 - self.joint_weight) * s_integrity
            + self.joint_weight * s_joint
        )
        return surprise, p_integrity, p_joint


class CalibratedStaticDetector(CalibratedSurprise):
    def __init__(self, world, config: StaticCalibratedConfig):
        super().__init__(world)
        self.config = config

    def observe(self, nf, sample, hierarchical_risk) -> bool:
        score, p_integrity, _ = self.evidence_features(
            nf, sample, hierarchical_risk
        )
        return (
            score >= self.config.threshold
            and p_integrity <= self.config.integrity_gate_p
        )


class EWMADetector(CalibratedSurprise):
    def __init__(self, world, config: EWMAConfig):
        super().__init__(world)
        self.config = config
        self.state = [0.0] * N_NF

    def observe(self, nf, sample, hierarchical_risk) -> bool:
        score, p_integrity, _ = self.evidence_features(
            nf, sample, hierarchical_risk
        )
        self.state[nf] = (
            (1.0 - self.config.alpha) * self.state[nf]
            + self.config.alpha * score
        )
        alarm = (
            self.state[nf] >= self.config.threshold
            and p_integrity <= self.config.integrity_gate_p
        )
        if alarm:
            self.state[nf] = 0.0
        return alarm


class CUSUMDetector(CalibratedSurprise):
    def __init__(self, world, config: CUSUMConfig):
        super().__init__(world)
        self.config = config
        self.state = [0.0] * N_NF

    def observe(self, nf, sample, hierarchical_risk) -> bool:
        score, p_integrity, _ = self.evidence_features(
            nf, sample, hierarchical_risk
        )
        self.state[nf] = max(
            0.0,
            self.state[nf] + score - self.config.reference,
        )
        alarm = (
            self.state[nf] >= self.config.threshold
            and p_integrity <= self.config.integrity_gate_p
        )
        if alarm:
            self.state[nf] = 0.0
        return alarm


class PageHinkleyDetector(CalibratedSurprise):
    def __init__(self, world, config: PageHinkleyConfig):
        super().__init__(world)
        self.config = config
        self.mean = [1.0] * N_NF
        self.cumulative = [0.0] * N_NF
        self.minimum = [0.0] * N_NF

    def observe(self, nf, sample, hierarchical_risk) -> bool:
        score, p_integrity, _ = self.evidence_features(
            nf, sample, hierarchical_risk
        )
        self.mean[nf] = (
            (1.0 - self.config.mean_alpha) * self.mean[nf]
            + self.config.mean_alpha * score
        )
        self.cumulative[nf] += (
            score - self.mean[nf] - self.config.delta
        )
        self.minimum[nf] = min(
            self.minimum[nf], self.cumulative[nf]
        )
        statistic = (
            self.cumulative[nf] - self.minimum[nf]
        )
        alarm = (
            statistic >= self.config.threshold
            and p_integrity <= self.config.integrity_gate_p
        )
        if alarm:
            self.cumulative[nf] = 0.0
            self.minimum[nf] = 0.0
        return alarm


def config_to_dict(config) -> dict:
    return dict(config.__dict__)


def detector_from_config(name: str, world, config: dict):
    if name == "calibrated_static":
        return CalibratedStaticDetector(
            world, StaticCalibratedConfig(**config)
        )
    if name == "ewma":
        return EWMADetector(world, EWMAConfig(**config))
    if name == "cusum":
        return CUSUMDetector(world, CUSUMConfig(**config))
    if name == "page_hinkley":
        return PageHinkleyDetector(
            world, PageHinkleyConfig(**config)
        )
    raise ValueError(name)
