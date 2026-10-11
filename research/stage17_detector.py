"""Stage 17 drift-adaptive e-Page detector.

The Stage-16 OOD audit showed two weaknesses of the frozen Stage-15 e-CUSUM:
its warm-up calibration became stale under post-warmup drift, and the
two-consecutive-tail gate sacrificed recall on sparse/micro attacks.

This detector keeps the same trusted integrity observations and conformal-style
warm-up ranks, but changes the sequential recurrence:

1. Convert integrity and hierarchical p-values to the same power-betting
   e-values used by Stage 15.
2. Work in log-evidence space.
3. Maintain a bounded, exponentially adaptive clean reference per NF.
   The reference update is winsorized so a strong attack cannot immediately
   drag the baseline toward itself.
4. Apply a Page-Hinkley cumulative-minus-minimum statistic to log evidence
   relative to that adaptive reference.
5. Require current integrity-tail corroboration for an alarm.

The construction is deliberately evaluated empirically; temporal dependence
and online adaptation mean no exact anytime-valid e-process guarantee is
claimed.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

from .stage15_detector import power_betting_mixture, upper_tail_rank
from .stage15_simulation import N_NF
from .stage16_detectors import CalibratedSurprise


@dataclass(frozen=True)
class AdaptiveEPageConfig:
    mean_alpha: float
    delta: float
    threshold: float
    integrity_gate_p: float
    update_log_cap: float
    joint_weight: float = 0.30


class DriftAdaptiveEPageDetector(CalibratedSurprise):
    """Page-Hinkley recurrence over adaptively centered log e-evidence."""

    def __init__(self, world, config: AdaptiveEPageConfig):
        super().__init__(world)
        self.config = config

        # Build a global clean reference from the exact warm-up calibration
        # distribution.  Online per-NF references then adapt from this point.
        warm_log_e = []
        for d, joint in zip(
            self.integrity_calibration,
            self.joint_calibration,
        ):
            from .stage15_detector import upper_tail_rank

            p_i = upper_tail_rank(
                self.integrity_calibration, d
            )
            p_j = upper_tail_rank(
                self.joint_calibration, joint
            )
            e_i = power_betting_mixture(p_i)
            e_j = power_betting_mixture(p_j)
            e_value = (
                (1.0 - config.joint_weight) * e_i
                + config.joint_weight * e_j
            )
            warm_log_e.append(math.log(max(1e-12, e_value)))

        warm_reference = sum(warm_log_e) / max(
            1, len(warm_log_e)
        )
        self.reference = [warm_reference] * N_NF
        self.cumulative = [0.0] * N_NF
        self.minimum = [0.0] * N_NF

    def evidence_log_value(
        self,
        nf: int,
        sample,
        hierarchical_risk: float,
    ) -> tuple[float, float]:
        _, p_integrity, p_joint = self.evidence_features(
            nf, sample, hierarchical_risk
        )
        e_integrity = power_betting_mixture(p_integrity)
        e_joint = power_betting_mixture(p_joint)
        e_value = (
            (1.0 - self.config.joint_weight) * e_integrity
            + self.config.joint_weight * e_joint
        )
        return (
            math.log(max(1e-12, e_value)),
            p_integrity,
        )

    def observe(
        self,
        nf: int,
        sample,
        hierarchical_risk: float,
    ) -> bool:
        log_e, p_integrity = self.evidence_log_value(
            nf, sample, hierarchical_risk
        )

        # Evaluate the change statistic against the *previous* reference.
        self.cumulative[nf] += (
            log_e
            - self.reference[nf]
            - self.config.delta
        )
        self.minimum[nf] = min(
            self.minimum[nf],
            self.cumulative[nf],
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
        else:
            # Winsorized adaptation follows benign distribution shift while
            # limiting how quickly an extreme event can poison the reference.
            bounded = min(
                log_e,
                self.reference[nf]
                + self.config.update_log_cap,
            )
            self.reference[nf] = (
                (1.0 - self.config.mean_alpha)
                * self.reference[nf]
                + self.config.mean_alpha * bounded
            )

        return alarm


ADAPTIVE_EPAGE_GRID = tuple(
    AdaptiveEPageConfig(
        mean_alpha=alpha,
        delta=delta,
        threshold=threshold,
        integrity_gate_p=gate,
        update_log_cap=cap,
    )
    for alpha in (0.02, 0.05, 0.10, 0.18)
    for delta in (0.02, 0.06, 0.12, 0.20)
    for threshold in (0.8, 1.3, 2.0, 3.0, 4.5, 6.5)
    for gate in (0.03, 0.06, 0.10)
    for cap in (0.35, 0.70, 1.20)
)


@dataclass(frozen=True)
class EAssistedPageConfig:
    """Page-Hinkley with a decaying positive log-e assistance channel."""

    mean_alpha: float
    delta: float
    threshold: float
    integrity_gate_p: float
    e_decay: float
    e_gain: float
    max_threshold_discount: float = 0.50
    joint_weight: float = 0.30


class EAssistedPageHinkleyDetector(CalibratedSurprise):
    """Drift-adaptive PH whose threshold is modulated by persistent e-evidence.

    Page-Hinkley remains the primary drift-aware change statistic. A second
    memory integrates only positive log e-evidence. Isolated clean spikes decay
    quickly; repeated integrity evidence lowers the PH alarm threshold by at
    most the configured maximum discount.
    """

    def __init__(self, world, config: EAssistedPageConfig):
        super().__init__(world)
        self.config = config
        self.mean = [1.0] * N_NF
        self.cumulative = [0.0] * N_NF
        self.minimum = [0.0] * N_NF
        self.e_memory = [0.0] * N_NF

    def observe(
        self,
        nf: int,
        sample,
        hierarchical_risk: float,
    ) -> bool:
        surprise, p_integrity, p_joint = self.evidence_features(
            nf, sample, hierarchical_risk
        )

        self.mean[nf] = (
            (1.0 - self.config.mean_alpha) * self.mean[nf]
            + self.config.mean_alpha * surprise
        )
        self.cumulative[nf] += (
            surprise - self.mean[nf] - self.config.delta
        )
        self.minimum[nf] = min(
            self.minimum[nf], self.cumulative[nf]
        )
        ph_statistic = (
            self.cumulative[nf] - self.minimum[nf]
        )

        e_integrity = power_betting_mixture(p_integrity)
        e_joint = power_betting_mixture(p_joint)
        e_value = (
            (1.0 - self.config.joint_weight) * e_integrity
            + self.config.joint_weight * e_joint
        )
        positive_log_e = max(
            0.0, math.log(max(1e-12, e_value))
        )
        self.e_memory[nf] = (
            self.config.e_decay * self.e_memory[nf]
            + positive_log_e
        )

        discount = min(
            self.config.max_threshold_discount,
            self.config.e_gain * self.e_memory[nf],
        )
        effective_threshold = (
            self.config.threshold * (1.0 - discount)
        )

        alarm = (
            ph_statistic >= effective_threshold
            and p_integrity <= self.config.integrity_gate_p
        )
        if alarm:
            self.cumulative[nf] = 0.0
            self.minimum[nf] = 0.0
            self.e_memory[nf] = 0.0

        return alarm


E_ASSISTED_PAGE_GRID = tuple(
    EAssistedPageConfig(
        mean_alpha=alpha,
        delta=delta,
        threshold=threshold,
        integrity_gate_p=gate,
        e_decay=decay,
        e_gain=gain,
    )
    for alpha in (0.07, 0.10)
    for delta in (0.40, 0.50, 0.60)
    for threshold in (8.0, 10.0, 12.0)
    for gate in (0.06, 0.08, 0.10)
    for decay in (0.50, 0.70, 0.85)
    for gain in (0.10, 0.20, 0.30)
)


@dataclass(frozen=True)
class EConfirmedPageConfig:
    """Low-threshold Page-Hinkley requiring accumulated e-confirmation."""

    mean_alpha: float
    delta: float
    threshold: float
    integrity_gate_p: float
    e_decay: float
    e_confirm_threshold: float
    joint_weight: float = 0.30


class EConfirmedPageHinkleyDetector(CalibratedSurprise):
    """Page-Hinkley with a decaying e-memory used as an alarm confirmation.

    Unlike EAssistedPageHinkleyDetector, e-evidence does not lower the change
    threshold. Instead the PH threshold can be lower, while an alarm requires
    both current integrity-tail evidence and accumulated positive log e-value.
    This is intended to reject isolated reconciliation outliers.
    """

    def __init__(self, world, config: EConfirmedPageConfig):
        super().__init__(world)
        self.config = config
        self.mean = [1.0] * N_NF
        self.cumulative = [0.0] * N_NF
        self.minimum = [0.0] * N_NF
        self.e_memory = [0.0] * N_NF

    def observe(
        self,
        nf: int,
        sample,
        hierarchical_risk: float,
    ) -> bool:
        surprise, p_integrity, p_joint = self.evidence_features(
            nf, sample, hierarchical_risk
        )
        self.mean[nf] = (
            (1.0 - self.config.mean_alpha) * self.mean[nf]
            + self.config.mean_alpha * surprise
        )
        self.cumulative[nf] += (
            surprise - self.mean[nf] - self.config.delta
        )
        self.minimum[nf] = min(
            self.minimum[nf], self.cumulative[nf]
        )
        ph_statistic = (
            self.cumulative[nf] - self.minimum[nf]
        )

        e_integrity = power_betting_mixture(p_integrity)
        e_joint = power_betting_mixture(p_joint)
        e_value = (
            (1.0 - self.config.joint_weight) * e_integrity
            + self.config.joint_weight * e_joint
        )
        self.e_memory[nf] = (
            self.config.e_decay * self.e_memory[nf]
            + max(0.0, math.log(max(1e-12, e_value)))
        )

        alarm = (
            ph_statistic >= self.config.threshold
            and p_integrity <= self.config.integrity_gate_p
            and self.e_memory[nf]
            >= self.config.e_confirm_threshold
        )
        if alarm:
            self.cumulative[nf] = 0.0
            self.minimum[nf] = 0.0
            self.e_memory[nf] = 0.0

        return alarm


E_CONFIRMED_PAGE_GRID = tuple(
    EConfirmedPageConfig(
        mean_alpha=alpha,
        delta=delta,
        threshold=threshold,
        integrity_gate_p=gate,
        e_decay=decay,
        e_confirm_threshold=e_threshold,
    )
    for alpha in (0.07, 0.10)
    for delta in (0.35, 0.50, 0.65)
    for threshold in (4.0, 5.5, 7.0, 8.5)
    for gate in (0.06, 0.08, 0.10)
    for decay in (0.50, 0.70, 0.85)
    for e_threshold in (0.35, 0.70, 1.10, 1.60)
)


@dataclass(frozen=True)
class DirectionalEConfig:
    """Two-sided directional log-e accumulation configuration."""

    decay: float
    reference: float
    threshold: float
    direction_gate_p: float


def signed_discrepancy(sample) -> float:
    """Signed NF-report minus trusted-transit discrepancy."""
    return (
        sample.reported - sample.transit
    ) / max(1, sample.transit)


def lower_tail_rank(calibration: list[float], value: float) -> float:
    return (
        1 + sum(item <= value for item in calibration)
    ) / (len(calibration) + 1)


class DirectionalEProcessDetector(CalibratedSurprise):
    """Accumulate one-sided e-evidence separately for over/under-reporting.

    Absolute-discrepancy detectors discard attack direction. Here the positive
    and negative tails have independent sequential states. Symmetric clean
    observer noise tends to alternate direction, while a persistent attack
    repeatedly feeds the same state.
    """

    def __init__(self, world, config: DirectionalEConfig):
        super().__init__(world)
        self.config = config
        self.positive = [0.0] * N_NF
        self.negative = [0.0] * N_NF

        self.signed_calibration = []
        from .stage15_simulation import WARMUP, STEP_SECONDS
        from .stage16_simulation import fixed_schedule

        for tick, row in enumerate(
            world.samples[: WARMUP // STEP_SECONDS]
        ):
            for nf in fixed_schedule(tick):
                self.signed_calibration.append(
                    signed_discrepancy(row[nf])
                )

    def observe(
        self,
        nf: int,
        sample,
        hierarchical_risk: float,
    ) -> bool:
        value = signed_discrepancy(sample)
        p_positive = upper_tail_rank(
            self.signed_calibration, value
        )
        p_negative = lower_tail_rank(
            self.signed_calibration, value
        )

        log_e_positive = math.log(
            max(1e-12, power_betting_mixture(p_positive))
        )
        log_e_negative = math.log(
            max(1e-12, power_betting_mixture(p_negative))
        )

        self.positive[nf] = max(
            0.0,
            self.config.decay * self.positive[nf]
            + log_e_positive
            - self.config.reference,
        )
        self.negative[nf] = max(
            0.0,
            self.config.decay * self.negative[nf]
            + log_e_negative
            - self.config.reference,
        )

        positive_alarm = (
            self.positive[nf] >= self.config.threshold
            and p_positive <= self.config.direction_gate_p
        )
        negative_alarm = (
            self.negative[nf] >= self.config.threshold
            and p_negative <= self.config.direction_gate_p
        )
        alarm = positive_alarm or negative_alarm
        if alarm:
            self.positive[nf] = 0.0
            self.negative[nf] = 0.0
        return alarm


DIRECTIONAL_E_GRID = tuple(
    DirectionalEConfig(
        decay=decay,
        reference=reference,
        threshold=threshold,
        direction_gate_p=gate,
    )
    for decay in (0.80, 0.90, 0.97, 1.00)
    for reference in (0.00, 0.05, 0.12, 0.22)
    for threshold in (1.5, 2.5, 3.5, 5.0, 7.0)
    for gate in (0.03, 0.06, 0.10)
)
