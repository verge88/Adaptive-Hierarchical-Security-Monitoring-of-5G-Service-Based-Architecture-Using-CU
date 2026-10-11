"""Stage 19 multiscale directional e-memory.

Stage 18 showed that the Stage-17 directional e-process transfers to genuine
Open5GS/SCP traffic for persistent signed tampering but misses sparse mutations.

The Stage-19 detector keeps separate positive/negative evidence and adds two
time scales per direction:

- fast state: responds to persistent directional corruption;
- slow state: retains sparse tail-supported evidence across benign gaps.

Both states consume the same one-sided conformal-style p-values and power
betting e-values.  The slow state only receives positive log-evidence when the
current observation is already in the configured directional tail; otherwise
it decays.  An alarm still requires a current directional-tail observation, so
stale evidence cannot trigger by itself.

No Stage-18 live artifacts are used by this module or its development search.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

from .stage15_detector import power_betting_mixture, upper_tail_rank


def lower_tail_rank(calibration: list[float], value: float) -> float:
    return (
        1 + sum(item <= value for item in calibration)
    ) / (len(calibration) + 1)


@dataclass(frozen=True)
class MultiscaleDirectionalConfig:
    fast_decay: float
    fast_reference: float
    fast_threshold: float
    slow_decay: float
    slow_reference: float
    slow_threshold: float
    direction_gate_p: float
    slow_update_gate_p: float


class MultiscaleDirectionalState:
    """State machine independent of any simulator or live transport."""

    def __init__(
        self,
        calibration: list[float],
        config: MultiscaleDirectionalConfig,
    ):
        if not calibration:
            raise ValueError("Calibration cannot be empty")
        self.calibration = list(calibration)
        self.config = config
        self.fast_positive = 0.0
        self.fast_negative = 0.0
        self.slow_positive = 0.0
        self.slow_negative = 0.0

    def observe(self, value: float) -> dict:
        p_positive = upper_tail_rank(
            self.calibration, value
        )
        p_negative = lower_tail_rank(
            self.calibration, value
        )

        log_e_positive = math.log(
            max(
                1e-12,
                power_betting_mixture(p_positive),
            )
        )
        log_e_negative = math.log(
            max(
                1e-12,
                power_betting_mixture(p_negative),
            )
        )

        self.fast_positive = max(
            0.0,
            self.config.fast_decay * self.fast_positive
            + log_e_positive
            - self.config.fast_reference,
        )
        self.fast_negative = max(
            0.0,
            self.config.fast_decay * self.fast_negative
            + log_e_negative
            - self.config.fast_reference,
        )

        slow_positive_increment = (
            max(0.0, log_e_positive)
            if p_positive <= self.config.slow_update_gate_p
            else 0.0
        )
        slow_negative_increment = (
            max(0.0, log_e_negative)
            if p_negative <= self.config.slow_update_gate_p
            else 0.0
        )

        self.slow_positive = max(
            0.0,
            self.config.slow_decay * self.slow_positive
            + slow_positive_increment
            - self.config.slow_reference,
        )
        self.slow_negative = max(
            0.0,
            self.config.slow_decay * self.slow_negative
            + slow_negative_increment
            - self.config.slow_reference,
        )

        positive_alert = (
            p_positive <= self.config.direction_gate_p
            and (
                self.fast_positive
                >= self.config.fast_threshold
                or self.slow_positive
                >= self.config.slow_threshold
            )
        )
        negative_alert = (
            p_negative <= self.config.direction_gate_p
            and (
                self.fast_negative
                >= self.config.fast_threshold
                or self.slow_negative
                >= self.config.slow_threshold
            )
        )
        alert = positive_alert or negative_alert

        record = {
            "p_positive": p_positive,
            "p_negative": p_negative,
            "fast_positive": self.fast_positive,
            "fast_negative": self.fast_negative,
            "slow_positive": self.slow_positive,
            "slow_negative": self.slow_negative,
            "positive_alert": positive_alert,
            "negative_alert": negative_alert,
            "alert": alert,
        }

        if alert:
            self.fast_positive = 0.0
            self.fast_negative = 0.0
            self.slow_positive = 0.0
            self.slow_negative = 0.0

        return record


MULTISCALE_GRID = tuple(
    MultiscaleDirectionalConfig(
        # Preserve the Stage-17 fast channel exactly; tune only the new
        # sparse-evidence memory.
        fast_decay=0.90,
        fast_reference=0.12,
        fast_threshold=5.0,
        slow_decay=slow_decay,
        slow_reference=slow_reference,
        slow_threshold=slow_threshold,
        direction_gate_p=gate,
        slow_update_gate_p=slow_gate,
    )
    for slow_decay in (0.96, 0.98, 0.995)
    for slow_reference in (0.00, 0.03, 0.06)
    for slow_threshold in (2.5, 3.5, 4.5, 6.0)
    for gate in (0.04, 0.06, 0.08)
    for slow_gate in (0.06, 0.10, 0.15)
)


@dataclass(frozen=True)
class SparseClusterDirectionalConfig:
    """Stage-17 fast e-process plus a bounded same-direction tail-hit memory."""

    cluster_decay: float
    cluster_threshold: float
    direction_gate_p: float
    cluster_update_gate_p: float


class SparseClusterDirectionalState:
    """Persistent e-process plus sparse same-direction hit clustering.

    The persistent path is exactly Stage 17.  The sparse path receives at most
    one unit from any observation, regardless of how extreme its p-value is.
    This prevents one heavy-tailed benign outlier from dominating the slow
    state while allowing separated same-direction tail hits to accumulate.
    """

    def __init__(
        self,
        calibration: list[float],
        config: SparseClusterDirectionalConfig,
    ):
        if not calibration:
            raise ValueError("Calibration cannot be empty")
        self.calibration = list(calibration)
        self.config = config
        self.fast_positive = 0.0
        self.fast_negative = 0.0
        self.cluster_positive = 0.0
        self.cluster_negative = 0.0

    def observe(self, value: float) -> dict:
        p_positive = upper_tail_rank(
            self.calibration, value
        )
        p_negative = lower_tail_rank(
            self.calibration, value
        )
        log_e_positive = math.log(
            max(1e-12, power_betting_mixture(p_positive))
        )
        log_e_negative = math.log(
            max(1e-12, power_betting_mixture(p_negative))
        )

        self.fast_positive = max(
            0.0,
            0.90 * self.fast_positive
            + log_e_positive
            - 0.12,
        )
        self.fast_negative = max(
            0.0,
            0.90 * self.fast_negative
            + log_e_negative
            - 0.12,
        )

        self.cluster_positive = (
            self.config.cluster_decay
            * self.cluster_positive
            + (
                1.0
                if p_positive
                <= self.config.cluster_update_gate_p
                else 0.0
            )
        )
        self.cluster_negative = (
            self.config.cluster_decay
            * self.cluster_negative
            + (
                1.0
                if p_negative
                <= self.config.cluster_update_gate_p
                else 0.0
            )
        )

        positive_alert = (
            p_positive <= self.config.direction_gate_p
            and (
                self.fast_positive >= 5.0
                or self.cluster_positive
                >= self.config.cluster_threshold
            )
        )
        negative_alert = (
            p_negative <= self.config.direction_gate_p
            and (
                self.fast_negative >= 5.0
                or self.cluster_negative
                >= self.config.cluster_threshold
            )
        )
        alert = positive_alert or negative_alert

        record = {
            "p_positive": p_positive,
            "p_negative": p_negative,
            "fast_positive": self.fast_positive,
            "fast_negative": self.fast_negative,
            "cluster_positive": self.cluster_positive,
            "cluster_negative": self.cluster_negative,
            "positive_alert": positive_alert,
            "negative_alert": negative_alert,
            "alert": alert,
        }

        if alert:
            self.fast_positive = 0.0
            self.fast_negative = 0.0
            self.cluster_positive = 0.0
            self.cluster_negative = 0.0

        return record


SPARSE_CLUSTER_GRID = tuple(
    SparseClusterDirectionalConfig(
        cluster_decay=decay,
        cluster_threshold=threshold,
        direction_gate_p=gate,
        cluster_update_gate_p=update_gate,
    )
    for decay in (0.85, 0.90, 0.95, 0.98)
    for threshold in (1.8, 2.2, 2.6, 3.0, 3.5)
    for gate in (0.04, 0.06)
    for update_gate in (0.04, 0.06, 0.10)
)
