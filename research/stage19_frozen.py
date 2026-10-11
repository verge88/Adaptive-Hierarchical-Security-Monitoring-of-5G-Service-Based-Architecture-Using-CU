"""Stage 19 frozen Tri-Path Directional Evidence Ensemble.

All parameters in this module were selected exclusively on development seeds
9001..9040.  The predeclared synthetic final block is 10001..10200.

No selection, tuning or fallback logic exists here.

The ensemble OR-combines three independently stateful channels:
1. adaptive robust multiscale sparse e-scan;
2. single-scale raw directional e-process;
3. adaptive short-window consecutive directional confirmation.

Each channel resets only on its own alarm, matching the development-time
union-of-alarm-streams evaluation.
"""
from __future__ import annotations

from dataclasses import dataclass

from .stage19_detector import (
    AdaptiveConsecutiveConfig,
    AdaptiveConsecutiveDirectionalDetector,
    AdaptiveRobustSparseEScanConfig,
    AdaptiveRobustSparseEScanDetector,
    ScalarPageHinkleyConfig,
    ScalarPageHinkleyDetector,
    SingleScaleDirectionalConfig,
    SingleScaleDirectionalDetector,
)

FINAL_START_SEED = 10001
FINAL_SEEDS = 200

FROZEN_SPARSE = AdaptiveRobustSparseEScanConfig(
    windows=(16, 32, 64),
    tail_gate_p=0.07,
    magnitude_gate_z=4.5,
    min_hits=2,
    e_sum_threshold=2.8,
    center_alpha=0.03,
    scale_alpha=0.02,
    update_clip_z=3.0,
)

FROZEN_SINGLE = SingleScaleDirectionalConfig(
    decay=0.90,
    reference=0.12,
    threshold=7.0,
    direction_gate_p=0.04,
)

FROZEN_CONSECUTIVE = AdaptiveConsecutiveConfig(
    window=4,
    hits=3,
    magnitude_gate_z=2.6,
    tail_gate_p=0.15,
    center_alpha=0.03,
    scale_alpha=0.02,
    update_clip_z=3.0,
)

# Strong comparator selected on the same Stage-19 development block.
FROZEN_PAGE_HINKLEY = ScalarPageHinkleyConfig(
    delta=0.30,
    threshold=5.0,
    gate_p=0.08,
    mean_alpha=0.20,
)


class TriPathDirectionalEvidenceEnsemble:
    """Frozen Stage-19 detector candidate."""

    def __init__(self, calibration: list[float]):
        self.sparse = AdaptiveRobustSparseEScanDetector(
            calibration,
            FROZEN_SPARSE,
        )
        self.single = SingleScaleDirectionalDetector(
            calibration,
            FROZEN_SINGLE,
        )
        self.consecutive = AdaptiveConsecutiveDirectionalDetector(
            calibration,
            FROZEN_CONSECUTIVE,
        )

    def observe(self, value: float) -> tuple[bool, dict]:
        sparse_alarm, sparse_state = self.sparse.observe(value)
        single_alarm, single_state = self.single.observe(value)
        consecutive_alarm, consecutive_state = (
            self.consecutive.observe(value)
        )
        alarm = (
            sparse_alarm
            or single_alarm
            or consecutive_alarm
        )
        return alarm, {
            "sparse_alarm": sparse_alarm,
            "single_alarm": single_alarm,
            "consecutive_alarm": consecutive_alarm,
            "sparse": sparse_state,
            "single": single_state,
            "consecutive": consecutive_state,
        }


def frozen_single_detector(
    calibration: list[float],
) -> SingleScaleDirectionalDetector:
    return SingleScaleDirectionalDetector(
        calibration,
        FROZEN_SINGLE,
    )


def frozen_page_hinkley_detector(
    calibration: list[float],
) -> ScalarPageHinkleyDetector:
    return ScalarPageHinkleyDetector(
        [abs(value) for value in calibration],
        FROZEN_PAGE_HINKLEY,
    )
