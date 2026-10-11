"""Stage 15 detectors: tuned static baseline and hierarchical e-CUSUM.

The new detector is intentionally different from the Stage-1 point-threshold
rule.  It turns warm-up ranks into upper-tail conformal-style p-values, maps
them to a convex mixture of power-betting e-values, and accumulates evidence
with a CUSUM-style e-process per NF.  A second, hierarchical nonconformity
channel may amplify integrity evidence with passive zone/processing context,
but an alarm additionally requires persistent integrity-tail evidence.  This
prevents a benign latency burst from becoming an alarm by itself.

Because Stage-15 traces contain temporal dependence and drift, the implementation
does NOT claim exact distribution-free anytime validity.  The e-value machinery
is used as a principled sequential evidence construction and is evaluated on
held-out seeds.
"""
from __future__ import annotations

from dataclasses import dataclass
import statistics

from .stage15_simulation import (
    CHALLENGES_PER_TICK,
    DURATION,
    N_NF,
    STEP_SECONDS,
    WARMUP,
    PassiveRisk,
    Sample,
    WorldV2,
    fixed_schedule,
)


@dataclass(frozen=True)
class StaticConfig:
    high_discrepancy: float = 0.13
    low_discrepancy: float = 0.085
    risk_threshold: float = 0.60


@dataclass(frozen=True)
class EvidenceConfig:
    threshold: float = 600.0
    joint_weight: float = 0.30
    integrity_gate_p: float = 0.03
    joint_risk_weight: float = 0.16
    joint_processing_weight: float = 0.05


LEGACY_STATIC = StaticConfig(
    high_discrepancy=0.19,
    low_discrepancy=0.075,
    risk_threshold=1.00,
)

# Selected only on tuning seeds 1001..1020; held-out seeds start at 2001.
TUNED_STATIC = StaticConfig()
HIERARCHICAL_E_CUSUM = EvidenceConfig()


def discrepancy(sample: Sample) -> float:
    return abs(sample.transit - sample.reported) / max(1, sample.transit)


def upper_tail_rank(calibration: list[float], value: float) -> float:
    """Add-one empirical upper-tail rank.

    For exchangeable clean observations this is the standard smoothed
    conformal rank form.  We use it here as a finite-sample calibration device.
    """
    return (
        1 + sum(item >= value for item in calibration)
    ) / (len(calibration) + 1)


def power_betting_mixture(p_value: float) -> float:
    """Convex mixture of power-betting e-values.

    For an exactly uniform p-value each beta * p**(beta-1) has expectation one.
    Mixing three bet sizes avoids selecting a single attack strength.
    """
    p_value = max(1e-12, min(1.0, p_value))
    return sum(
        beta * p_value ** (beta - 1)
        for beta in (0.25, 0.50, 0.75)
    ) / 3.0


class StaticThresholdDetector:
    """Strong static comparator using the original detector family."""

    def __init__(self, world: WorldV2, config: StaticConfig):
        self.risk = PassiveRisk(world)
        self.config = config

    def observe(
        self,
        nf: int,
        sample: Sample,
        hierarchical_risk: float,
    ) -> bool:
        d = discrepancy(sample)
        return (
            d > self.config.high_discrepancy
            or (
                d > self.config.low_discrepancy
                and hierarchical_risk > self.config.risk_threshold
            )
        )


class HierarchicalECUSUMDetector:
    """Sequential integrity detector with hierarchical corroboration.

    The primary channel is the CU/SCP-vs-NF counter discrepancy.  The joint
    channel multiplies the discrepancy by bounded passive risk and processing
    evidence.  Both channels are calibrated from the same fixed-budget warm-up
    schedule.  A convex e-value mixture is accumulated via a max-reset
    e-CUSUM recurrence; isolated passive anomalies cannot trigger an alarm.
    """

    def __init__(
        self,
        world: WorldV2,
        config: EvidenceConfig = HIERARCHICAL_E_CUSUM,
    ):
        self.risk = PassiveRisk(world)
        self.config = config
        self.statistic = [1.0] * N_NF
        self.previous_integrity_tail = [False] * N_NF

        calibration_risk = PassiveRisk(world)
        self.discrepancy_calibration: list[float] = []
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
                self.discrepancy_calibration.append(d)
                self.joint_calibration.append(joint)

        expected_calibration = (
            WARMUP // STEP_SECONDS
        ) * CHALLENGES_PER_TICK
        if len(self.discrepancy_calibration) != expected_calibration:
            raise AssertionError("Unexpected warm-up CU calibration budget")

    def _joint_score(
        self,
        risk_model: PassiveRisk,
        nf: int,
        sample: Sample,
        hierarchical_risk: float,
        d: float,
    ) -> float:
        proc_z = risk_model.processing_z(nf, sample)
        return d * (
            1.0
            + self.config.joint_risk_weight
            * min(6.0, hierarchical_risk)
            + self.config.joint_processing_weight
            * min(6.0, proc_z)
        )

    def observe(
        self,
        nf: int,
        sample: Sample,
        hierarchical_risk: float,
    ) -> bool:
        d = discrepancy(sample)
        joint = self._joint_score(
            self.risk,
            nf,
            sample,
            hierarchical_risk,
            d,
        )
        p_integrity = upper_tail_rank(
            self.discrepancy_calibration, d
        )
        p_joint = upper_tail_rank(self.joint_calibration, joint)

        e_integrity = power_betting_mixture(p_integrity)
        e_joint = power_betting_mixture(p_joint)
        e_value = (
            (1.0 - self.config.joint_weight) * e_integrity
            + self.config.joint_weight * e_joint
        )

        updated = max(1.0, self.statistic[nf]) * e_value
        integrity_tail = (
            p_integrity <= self.config.integrity_gate_p
        )
        alarm = (
            updated >= self.config.threshold
            and integrity_tail
            and self.previous_integrity_tail[nf]
        )

        self.statistic[nf] = 1.0 if alarm else updated
        self.previous_integrity_tail[nf] = integrity_tail
        return alarm


def evaluate_detector(
    world: WorldV2,
    detector,
) -> dict:
    """Evaluate one detector with a fixed, detector-independent CU schedule."""
    found = {attack.nf: None for attack in world.attacks}
    tp = fp = fn = tn = 0

    for tick, row in enumerate(world.samples):
        t = tick * STEP_SECONDS
        if t < WARMUP:
            continue

        hierarchical = detector.risk.risks(row)
        for nf in fixed_schedule(tick):
            alert = detector.observe(
                nf,
                row[nf],
                hierarchical[nf],
            )
            attacked = world.active_attack(nf, t)
            if attacked:
                if alert:
                    tp += 1
                    if found[nf] is None:
                        found[nf] = t
                else:
                    fn += 1
            elif alert:
                fp += 1
            else:
                tn += 1

    delays = [
        (
            found[attack.nf] - attack.start
            if found[attack.nf] is not None
            else DURATION - attack.start
        )
        for attack in world.attacks
    ]
    detected = sum(
        found[attack.nf] is not None
        for attack in world.attacks
    )
    sample_precision = tp / max(1, tp + fp)
    sample_recall = tp / max(1, tp + fn)

    return {
        "seed": world.seed,
        "attacks": len(world.attacks),
        "detected": detected,
        "event_recall": detected / len(world.attacks),
        "mean_censored_delay_s": statistics.mean(delays),
        "median_censored_delay_s": statistics.median(delays),
        "false_alarms_per_1000_clean_checks": (
            1000 * fp / max(1, fp + tn)
        ),
        "alarm_precision": sample_precision,
        "checked_sample_recall": sample_recall,
        "checked_sample_f1": (
            2
            * sample_precision
            * sample_recall
            / max(1e-12, sample_precision + sample_recall)
        ),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "probes": (
            (DURATION - WARMUP)
            // STEP_SECONDS
            * CHALLENGES_PER_TICK
        ),
    }


def run_seed(seed: int) -> list[dict]:
    world = WorldV2(seed)
    variants = (
        (
            "legacy_static",
            StaticThresholdDetector(world, LEGACY_STATIC),
        ),
        (
            "tuned_static",
            StaticThresholdDetector(world, TUNED_STATIC),
        ),
        (
            "hierarchical_e_cusum",
            HierarchicalECUSUMDetector(
                world, HIERARCHICAL_E_CUSUM
            ),
        ),
    )
    rows = []
    for name, detector in variants:
        result = evaluate_detector(world, detector)
        result["detector"] = name
        rows.append(result)
    return rows
