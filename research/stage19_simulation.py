"""Stage 19 sparse-rich signed-integrity development world.

This simulator is NEW development data.  It does not replay or inspect any
Stage-18 live artifact.  It generates a single signed integrity stream matching
the live detector interface: trusted-reference versus consumer-visible
accounting.

The benchmark intentionally mixes:
- persistent positive and negative shifts;
- sparse positive and negative pulse trains with variable spacing/amplitude;
- clean autocorrelation, slow drift, heteroscedasticity and rare symmetric
  outliers.

Attack labels are evaluator-only.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import random

WARMUP_TICKS = 30
EPISODE_TICKS = 18
GAP_TICKS = 8
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


@dataclass(frozen=True)
class SparseEpisode:
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


class SparseIntegrityWorld:
    def __init__(self, seed: int):
        self.seed = seed
        rng = random.Random(seed * 19019 + 37)

        kinds = [
            kind
            for kind in ALL_KINDS
            for _ in range(REPETITIONS_PER_KIND)
        ]
        rng.shuffle(kinds)

        self.episodes: list[SparseEpisode] = []
        cursor = WARMUP_TICKS
        for episode_id, kind in enumerate(kinds):
            start = cursor
            end = start + EPISODE_TICKS
            direction = 1 if kind.endswith("positive") else -1

            if kind in PERSISTENT_KINDS:
                pulses = tuple(range(EPISODE_TICKS))
                amplitude = rng.uniform(0.038, 0.078)
            elif kind.startswith("cluster_sparse"):
                # Two small clusters, positions vary by episode.
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
                amplitude = rng.uniform(0.075, 0.135)
            else:
                # 3-5 isolated pulses over a long episode.  Require at least
                # one clean tick between pulses to stress memory retention.
                count = rng.choice((3, 4, 5))
                candidates = list(range(1, EPISODE_TICKS - 1))
                rng.shuffle(candidates)
                selected = []
                for candidate in candidates:
                    if all(
                        abs(candidate - old) >= 2
                        for old in selected
                    ):
                        selected.append(candidate)
                        if len(selected) == count:
                            break
                if len(selected) < count:
                    raise AssertionError("Could not place sparse pulses")
                pulses = tuple(sorted(selected))
                amplitude = rng.uniform(0.085, 0.150)

            self.episodes.append(
                SparseEpisode(
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

        episode_by_tick = {}
        for episode in self.episodes:
            for local in range(EPISODE_TICKS):
                episode_by_tick[episode.start_tick + local] = (
                    episode,
                    local,
                )

        values: list[float] = []
        ar = 0.0
        for tick in range(self.total_ticks):
            # Clean process: AR(1) + two slow modes + variance drift.
            sigma = 0.0065 * (
                1.0 + 0.0009 * max(0, tick - WARMUP_TICKS)
            )
            ar = 0.67 * ar + rng.gauss(0.0, sigma)
            drift = (
                0.0040 * math.sin(2 * math.pi * tick / 113)
                + 0.0025 * math.sin(2 * math.pi * tick / 47)
            )
            clean = ar + drift

            # Rare clean outliers are symmetric and can be large enough to
            # create minimum-rank p-values.
            outlier_p = (
                0.004 if tick < WARMUP_TICKS else 0.010
            )
            if rng.random() < outlier_p:
                clean += rng.choice((-1, 1)) * rng.uniform(
                    0.045, 0.085
                )

            attack = 0.0
            item = episode_by_tick.get(tick)
            if item is not None:
                episode, local = item
                if local in episode.pulse_ticks:
                    # Pulse amplitude jitters independently, preserving sign.
                    attack = (
                        episode.direction
                        * episode.amplitude
                        * rng.uniform(0.82, 1.18)
                    )
                elif episode.kind in PERSISTENT_KINDS:
                    raise AssertionError(
                        "Persistent episode missing attack pulse"
                    )

            values.append(clean + attack)

        self.values = values

    def episode_for_tick(self, tick: int):
        for episode in self.episodes:
            if episode.start_tick <= tick < episode.end_tick:
                return episode
        return None

    def active_attack_tick(self, tick: int) -> bool:
        episode = self.episode_for_tick(tick)
        if episode is None:
            return False
        local = tick - episode.start_tick
        return local in episode.pulse_ticks
