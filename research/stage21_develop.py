"""Stage 21 conservative development for value-semantic integrity.

Fresh blocks only:
- stable tuning:     24001..24040
- race tuning:       24101..24140
- stable validation: 25001..25120
- race stress:       26001..26080

No historical Stage 17-20 live block or inspected Stage 20 synthetic block is
used. Selection requires zero false alarms in BOTH tuning regimes before
primary recall or delay are considered.

The boundary family cross_profile_identity_swap intentionally preserves the
normalized per-path value multiset and is reported separately, not optimized.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import json
from pathlib import Path
import random
import statistics

from .stage21_semantic import (
    SEMANTIC_GRID,
    SemanticQuorumConfig,
    SemanticQuorumState,
    semantic_projection,
)

WARMUP = 30
EPISODE_TICKS = 12
GAP_TICKS = 6
PRIMARY_FAMILIES = (
    "sparse_stable_string_change",
    "sparse_stable_number_change",
    "persistent_identity_substitution",
    "sparse_stable_bool_flip",
)
BOUNDARY_FAMILIES = ("cross_profile_identity_swap",)
PRIMARY_REPS = 3
BOUNDARY_REPS = 2
TOTAL_EPISODES = (
    len(PRIMARY_FAMILIES) * PRIMARY_REPS
    + len(BOUNDARY_FAMILIES) * BOUNDARY_REPS
)
TOTAL_TICKS = WARMUP + TOTAL_EPISODES * (
    EPISODE_TICKS + GAP_TICKS
)

STABLE_TUNE_START = 24001
STABLE_TUNE_SEEDS = 40
RACE_TUNE_START = 24101
RACE_TUNE_SEEDS = 40
VALID_START = 25001
VALID_SEEDS = 120
STRESS_START = 26001
STRESS_SEEDS = 80
FINAL_FA_CEILING = 0.50


@dataclass(frozen=True)
class Episode:
    family: str
    start: int
    end: int
    pulse_ticks: tuple[int, ...]


def _profile(index: int, tick: int) -> dict:
    return {
        "nfInstanceId": f"00000000-0000-0000-0000-{index + 1:012d}",
        "nfType": "NSSF",
        "nfStatus": "REGISTERED",
        "heartBeatTimer": 10 + index,
        "priority": 1,
        "allowed": True,
        "load": (tick * 7 + index * 13) % 101,
        "services": [
            {
                "serviceName": "nnssf-nsselection",
                "versions": [{"apiVersionInUri": "v2"}],
                "scheme": "http",
            }
        ],
    }


def base_payload(tick: int, version: int = 0) -> dict:
    payload = {
        "validityPeriod": 60,
        "nfInstances": [
            _profile(0, tick),
            _profile(1, tick),
        ],
        # Deliberately unstable values: these should not be selected as stable
        # semantic paths during warm-up.
        "serverTick": tick,
        "dynamicEpoch": f"epoch-{tick}",
    }
    if version % 2:
        # Legitimate schema evolution appears identically on both sides.
        payload["serverMetadata"] = {
            "schemaRevision": 2,
            "source": "nrf",
        }
    return payload


def apply_fault(payload: dict, family: str) -> dict:
    output = copy.deepcopy(payload)
    profiles = output["nfInstances"]
    first = profiles[0]

    if family == "sparse_stable_string_change":
        first["services"][0]["scheme"] = "grpc"
        return output

    if family == "sparse_stable_number_change":
        first["heartBeatTimer"] = 11
        return output

    if family == "persistent_identity_substitution":
        first["nfInstanceId"] = (
            "ffffffff-ffff-ffff-ffff-ffffffffffff"
        )
        return output

    if family == "sparse_stable_bool_flip":
        first["allowed"] = False
        return output

    if family == "cross_profile_identity_swap":
        profiles[0]["nfInstanceId"], profiles[1]["nfInstanceId"] = (
            profiles[1]["nfInstanceId"],
            profiles[0]["nfInstanceId"],
        )
        return output

    raise ValueError(family)


class SemanticWorld:
    def __init__(self, seed: int, *, race_stress: bool = False):
        self.seed = seed
        rng = random.Random(seed * 212121 + 97)
        kinds = [
            family
            for family in PRIMARY_FAMILIES
            for _ in range(PRIMARY_REPS)
        ] + [
            family
            for family in BOUNDARY_FAMILIES
            for _ in range(BOUNDARY_REPS)
        ]
        rng.shuffle(kinds)

        self.episodes: list[Episode] = []
        cursor = WARMUP
        for family in kinds:
            start = cursor
            end = start + EPISODE_TICKS
            if family in (
                "persistent_identity_substitution",
                "cross_profile_identity_swap",
            ):
                pulses = tuple(range(start, end))
            else:
                count = rng.choice((3, 4, 5))
                pulses = tuple(
                    start + offset
                    for offset in sorted(
                        rng.sample(range(EPISODE_TICKS), count)
                    )
                )
            self.episodes.append(
                Episode(family, start, end, pulses)
            )
            cursor = end + GAP_TICKS

        self.pairs = []
        for tick in range(TOTAL_TICKS):
            version = 1 if (tick // 43) % 2 else 0
            trusted = base_payload(tick, version)
            consumer = copy.deepcopy(trusted)

            # Nearby reference requests can observe benign dynamic values at
            # slightly different instants. The paths are intentionally
            # temporally unstable and should be excluded by calibration.
            consumer["serverTick"] = tick + 1
            consumer["dynamicEpoch"] = f"epoch-{tick + 1}"
            for index, profile in enumerate(consumer["nfInstances"]):
                profile["load"] = (
                    profile["load"] + 3 + index
                ) % 101

            # Rare legitimate registration race. A one-tick mismatch on a
            # normally stable identity path must not trigger by itself.
            race_probability = 0.001 if not race_stress else 0.025
            if rng.random() < race_probability:
                consumer["nfInstances"][1]["nfInstanceId"] = (
                    "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
                )

            episode = self.episode_for_tick(tick)
            if episode is not None and tick in episode.pulse_ticks:
                consumer = apply_fault(consumer, episode.family)

            self.pairs.append(
                (
                    semantic_projection(trusted),
                    semantic_projection(consumer),
                )
            )

    def episode_for_tick(self, tick: int):
        for episode in self.episodes:
            if episode.start <= tick < episode.end:
                return episode
        return None


def detector_outputs(
    world: SemanticWorld,
    config: SemanticQuorumConfig,
):
    state = SemanticQuorumState(
        world.pairs[:WARMUP],
        config,
    )
    alerts = []
    for tick, (trusted, consumer) in enumerate(world.pairs):
        if tick < WARMUP:
            alerts.append(False)
            continue
        alerts.append(state.observe(trusted, consumer)["alert"])
    return alerts, state


def evaluate(world: SemanticWorld, alerts: list[bool]):
    episode_ticks = {
        tick
        for episode in world.episodes
        for tick in range(episode.start, episode.end)
    }
    clean_ticks = set(range(WARMUP, TOTAL_TICKS)) - episode_ticks
    false_alarms = sum(alerts[tick] for tick in clean_ticks)

    primary_events = []
    boundary_events = []
    for episode in world.episodes:
        inside = [
            tick
            for tick in range(episode.start, episode.end)
            if alerts[tick]
        ]
        item = {
            "family": episode.family,
            "detected": bool(inside),
            "delay": (
                inside[0] - episode.start
                if inside
                else EPISODE_TICKS
            ),
        }
        if episode.family in PRIMARY_FAMILIES:
            primary_events.append(item)
        else:
            boundary_events.append(item)

    per_family = {}
    for family in PRIMARY_FAMILIES:
        rows = [x for x in primary_events if x["family"] == family]
        per_family[family] = statistics.mean(
            x["detected"] for x in rows
        )

    boundary_recall = {
        family: statistics.mean(
            x["detected"]
            for x in boundary_events
            if x["family"] == family
        )
        for family in BOUNDARY_FAMILIES
    }

    return {
        "event_recall": statistics.mean(
            x["detected"] for x in primary_events
        ),
        "min_family_recall": min(per_family.values()),
        "mean_horizon_penalized_delay": statistics.mean(
            x["delay"] for x in primary_events
        ),
        "false_alarms_per_1000": (
            1000 * false_alarms / max(1, len(clean_ticks))
        ),
        "per_family": per_family,
        "boundary_recall": boundary_recall,
    }


def evaluate_block(worlds, config):
    rows = []
    enabled = []
    selected_paths = []
    for world in worlds:
        alerts, state = detector_outputs(world, config)
        rows.append(evaluate(world, alerts))
        enabled.append(state.enabled)
        selected_paths.append(len(state.selected_paths))

    per_family = {
        family: statistics.mean(
            row["per_family"][family] for row in rows
        )
        for family in PRIMARY_FAMILIES
    }
    boundary = {
        family: statistics.mean(
            row["boundary_recall"][family] for row in rows
        )
        for family in BOUNDARY_FAMILIES
    }
    return {
        "event_recall": statistics.mean(
            row["event_recall"] for row in rows
        ),
        "min_family_recall": min(per_family.values()),
        "mean_horizon_penalized_delay": statistics.mean(
            row["mean_horizon_penalized_delay"] for row in rows
        ),
        "false_alarms_per_1000": statistics.mean(
            row["false_alarms_per_1000"] for row in rows
        ),
        "per_family": per_family,
        "boundary_recall": boundary,
        "enabled_fraction": statistics.mean(enabled),
        "mean_selected_path_count": statistics.mean(selected_paths),
    }


def select(candidates):
    feasible = [
        item
        for item in candidates
        if (
            item["stable_tuning"]["false_alarms_per_1000"] == 0.0
            and item["race_tuning"]["false_alarms_per_1000"] == 0.0
        )
    ]
    if not feasible:
        raise AssertionError(
            "No Stage21 semantic config achieved zero FA on both tuning regimes"
        )
    return max(
        feasible,
        key=lambda item: (
            item["stable_tuning"]["min_family_recall"],
            item["stable_tuning"]["event_recall"],
            -item["stable_tuning"]["mean_horizon_penalized_delay"],
            -item["race_tuning"]["enabled_fraction"],
        ),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage21_development.json",
    )
    args = parser.parse_args()

    stable_tuning = [
        SemanticWorld(seed)
        for seed in range(
            STABLE_TUNE_START,
            STABLE_TUNE_START + STABLE_TUNE_SEEDS,
        )
    ]
    race_tuning = [
        SemanticWorld(seed, race_stress=True)
        for seed in range(
            RACE_TUNE_START,
            RACE_TUNE_START + RACE_TUNE_SEEDS,
        )
    ]

    candidates = []
    for config in SEMANTIC_GRID:
        candidates.append(
            {
                "config": dict(config.__dict__),
                "stable_tuning": evaluate_block(
                    stable_tuning, config
                ),
                "race_tuning": evaluate_block(
                    race_tuning, config
                ),
            }
        )
    selected = select(candidates)
    config = SemanticQuorumConfig(**selected["config"])

    validation = evaluate_block(
        [
            SemanticWorld(seed)
            for seed in range(
                VALID_START, VALID_START + VALID_SEEDS
            )
        ],
        config,
    )
    stress = evaluate_block(
        [
            SemanticWorld(seed, race_stress=True)
            for seed in range(
                STRESS_START, STRESS_START + STRESS_SEEDS
            )
        ],
        config,
    )

    if validation["false_alarms_per_1000"] > FINAL_FA_CEILING:
        raise AssertionError(
            "Stage21 stable validation exceeds FA ceiling"
        )
    if stress["false_alarms_per_1000"] > FINAL_FA_CEILING:
        raise AssertionError(
            "Stage21 race stress exceeds FA ceiling"
        )

    result = {
        "protocol": {
            "forbidden_historical_live_blocks": [
                [7001, 7200],
                [8101, 8106],
                [8201, 8206],
                [8301, 8306],
            ],
            "forbidden_inspected_stage20_synthetic": [
                [18001, 19120],
                [20001, 20080],
                [21001, 23080],
            ],
            "stable_tuning_block": [24001, 24040],
            "race_tuning_block": [24101, 24140],
            "stable_validation_block": [25001, 25120],
            "race_stress_block": [26001, 26080],
            "zero_false_alarm_required_on_both_tuning_regimes": True,
            "final_false_alarm_ceiling_per_1000": FINAL_FA_CEILING,
            "boundary_family_excluded_from_selection": True,
        },
        "grid_size": len(SEMANTIC_GRID),
        "selected_detector": selected,
        "stable_validation": validation,
        "race_stress": stress,
    }
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
