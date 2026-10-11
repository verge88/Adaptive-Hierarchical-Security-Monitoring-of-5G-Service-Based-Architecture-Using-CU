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

from .stage15_detector import power_betting_mixture
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
