"""Stage 20 structural detector development.

No Stage-18 or Stage-19 live artifacts are read.

Fresh blocks:
- tuning:                 18001..18060
- structural validation: 19001..19120
- unstable-schema stress: 20001..20080

Selection requires zero false alarms on the entire tuning block, then maximizes
minimum family recall, overall recall, and finally minimizes penalized delay.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import json
from pathlib import Path
import random
import statistics

from .stage20_structure import (
    STRUCTURAL_GRID,
    StructuralQuorumConfig,
    StructuralQuorumState,
    structural_counter,
    structural_difference,
)

WARMUP = 30
EPISODE_TICKS = 12
GAP_TICKS = 6
FAMILIES = (
    "persistent_array_duplicate",
    "persistent_array_drop",
    "sparse_field_add",
    "sparse_field_delete",
)
REPS = 3
TOTAL_TICKS = WARMUP + len(FAMILIES) * REPS * (
    EPISODE_TICKS + GAP_TICKS
)

TUNE_START = 18001
TUNE_SEEDS = 60
VALID_START = 19001
VALID_SEEDS = 120
STRESS_START = 20001
STRESS_SEEDS = 80
FINAL_FA_CEILING = 0.50


@dataclass(frozen=True)
class Episode:
    family: str
    start: int
    end: int
    pulse_ticks: tuple[int, ...]


def base_payload(version: int = 0) -> dict:
    profile = {
        "nfInstanceId": "nf-template",
        "nfType": "NSSF",
        "nfStatus": "REGISTERED",
        "heartBeatTimer": 10,
        "priority": 1,
        "services": [
            {
                "serviceName": "nnssf-nsselection",
                "versions": [{"apiVersionInUri": "v2"}],
                "scheme": "http",
            }
        ],
    }
    payload = {
        "validityPeriod": 60,
        "nfInstances": [
            copy.deepcopy(profile),
            copy.deepcopy(profile),
        ],
        "searchId": "ignored-value",
    }
    if version % 2:
        # Benign schema version change that appears on BOTH sides.
        payload["serverMetadata"] = {
            "schemaRevision": 2,
            "source": "nrf",
        }
    return payload


def apply_consumer_fault(
    payload: dict,
    family: str,
) -> dict:
    output = copy.deepcopy(payload)
    instances = output["nfInstances"]

    if family == "persistent_array_duplicate":
        instances.append(copy.deepcopy(instances[0]))
        return output

    if family == "persistent_array_drop":
        if len(instances) > 1:
            instances.pop()
        return output

    if family == "sparse_field_add":
        output["_consumerOnlyMetadata"] = {
            "marker": True,
        }
        return output

    if family == "sparse_field_delete":
        # Delete a small optional leaf, not an entire object.
        service = instances[0]["services"][0]
        service.pop("scheme", None)
        return output

    raise ValueError(family)


class StructuralWorld:
    def __init__(
        self,
        seed: int,
        *,
        unstable_schema: bool = False,
    ):
        self.seed = seed
        rng = random.Random(seed * 202020 + 41)

        kinds = [
            family
            for family in FAMILIES
            for _ in range(REPS)
        ]
        rng.shuffle(kinds)

        self.episodes: list[Episode] = []
        cursor = WARMUP
        for family in kinds:
            start = cursor
            end = start + EPISODE_TICKS
            if family.startswith("persistent"):
                pulses = tuple(range(start, end))
            else:
                count = rng.choice((3, 4, 5))
                pulses = tuple(
                    start + index
                    for index in sorted(
                        rng.sample(
                            range(EPISODE_TICKS),
                            count,
                        )
                    )
                )
            self.episodes.append(
                Episode(
                    family=family,
                    start=start,
                    end=end,
                    pulse_ticks=pulses,
                )
            )
            cursor = end + GAP_TICKS

        pairs = []
        for tick in range(TOTAL_TICKS):
            version = 1 if (tick // 37) % 2 else 0
            trusted = base_payload(version)
            consumer = copy.deepcopy(trusted)

            # Paired benign schema churn is harmless.
            if rng.random() < 0.03:
                trusted["pairedEphemeral"] = {"v": 1}
                consumer["pairedEphemeral"] = {"v": 2}

            # Rare asynchronous structural skew challenges false alarms.
            skew_probability = 0.025 if unstable_schema else 0.001
            if rng.random() < skew_probability:
                consumer["transientConsumerField"] = {
                    "seen": True
                }

            episode = self.episode_for_tick(tick)
            if (
                episode is not None
                and tick in episode.pulse_ticks
            ):
                consumer = apply_consumer_fault(
                    consumer,
                    episode.family,
                )

            pairs.append(
                (
                    structural_counter(trusted),
                    structural_counter(consumer),
                )
            )

        self.pairs = pairs

    def episode_for_tick(self, tick: int):
        for episode in self.episodes:
            if episode.start <= tick < episode.end:
                return episode
        return None


def detector_outputs(
    world: StructuralWorld,
    config: StructuralQuorumConfig,
):
    warmup_diffs = [
        structural_difference(trusted, consumer)
        for trusted, consumer in world.pairs[:WARMUP]
    ]
    state = StructuralQuorumState(
        warmup_diffs,
        config,
    )
    alerts = []
    for tick, (trusted, consumer) in enumerate(world.pairs):
        if tick < WARMUP:
            alerts.append(False)
            continue
        diff = structural_difference(trusted, consumer)
        alerts.append(state.observe(diff)["alert"])
    return alerts, state.enabled, state.exact_fraction


def evaluate(world: StructuralWorld, alerts: list[bool]):
    attack_ticks = {
        tick
        for episode in world.episodes
        for tick in range(episode.start, episode.end)
    }
    clean_ticks = set(range(WARMUP, TOTAL_TICKS)) - attack_ticks
    false_alarms = sum(alerts[tick] for tick in clean_ticks)

    events = []
    for episode in world.episodes:
        inside = [
            tick
            for tick in range(episode.start, episode.end)
            if alerts[tick]
        ]
        detected = bool(inside)
        delay = (
            inside[0] - episode.start
            if detected
            else EPISODE_TICKS
        )
        events.append(
            {
                "family": episode.family,
                "detected": detected,
                "delay": delay,
            }
        )

    per_family = {}
    for family in FAMILIES:
        selected = [
            item
            for item in events
            if item["family"] == family
        ]
        per_family[family] = statistics.mean(
            item["detected"]
            for item in selected
        )

    return {
        "event_recall": statistics.mean(
            item["detected"] for item in events
        ),
        "min_family_recall": min(per_family.values()),
        "mean_horizon_penalized_delay": statistics.mean(
            item["delay"] for item in events
        ),
        "false_alarms_per_1000": (
            1000 * false_alarms / max(1, len(clean_ticks))
        ),
        "per_family": per_family,
    }


def summarize(rows):
    per_family = {
        family: statistics.mean(
            row["per_family"][family] for row in rows
        )
        for family in FAMILIES
    }
    return {
        "event_recall": statistics.mean(
            row["event_recall"] for row in rows
        ),
        "min_family_recall": min(per_family.values()),
        "mean_horizon_penalized_delay": statistics.mean(
            row["mean_horizon_penalized_delay"]
            for row in rows
        ),
        "false_alarms_per_1000": statistics.mean(
            row["false_alarms_per_1000"]
            for row in rows
        ),
        "per_family": per_family,
    }


def evaluate_block(worlds, config):
    rows = []
    enabled = []
    exact_fraction = []
    for world in worlds:
        alerts, active, exact = detector_outputs(
            world, config
        )
        rows.append(evaluate(world, alerts))
        enabled.append(active)
        exact_fraction.append(exact)
    summary = summarize(rows)
    summary["enabled_fraction"] = statistics.mean(enabled)
    summary["mean_warmup_exact_fraction"] = statistics.mean(
        exact_fraction
    )
    return summary


def select(candidates):
    zero_fa = [
        item
        for item in candidates
        if item["summary"]["false_alarms_per_1000"] == 0.0
    ]
    if not zero_fa:
        raise AssertionError(
            "No structural configuration achieved zero tuning false alarms"
        )
    return max(
        zero_fa,
        key=lambda item: (
            item["summary"]["min_family_recall"],
            item["summary"]["event_recall"],
            -item["summary"]["mean_horizon_penalized_delay"],
        ),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="stage20_development.json",
    )
    args = parser.parse_args()

    tuning = [
        StructuralWorld(seed)
        for seed in range(TUNE_START, TUNE_START + TUNE_SEEDS)
    ]
    candidates = []
    for config in STRUCTURAL_GRID:
        candidates.append(
            {
                "config": dict(config.__dict__),
                "summary": evaluate_block(
                    tuning, config
                ),
            }
        )
    selected = select(candidates)
    config = StructuralQuorumConfig(
        **selected["config"]
    )

    validation = [
        StructuralWorld(seed)
        for seed in range(
            VALID_START, VALID_START + VALID_SEEDS
        )
    ]
    validation_summary = evaluate_block(
        validation, config
    )

    stress = [
        StructuralWorld(seed, unstable_schema=True)
        for seed in range(
            STRESS_START, STRESS_START + STRESS_SEEDS
        )
    ]
    stress_summary = evaluate_block(
        stress, config
    )

    if (
        validation_summary["false_alarms_per_1000"]
        > FINAL_FA_CEILING
    ):
        raise AssertionError(
            "Structural validation exceeds final false-alarm ceiling"
        )
    if (
        stress_summary["false_alarms_per_1000"]
        > FINAL_FA_CEILING
    ):
        raise AssertionError(
            "Unstable-schema stress exceeds final false-alarm ceiling"
        )

    result = {
        "protocol": {
            "tuning_block": [
                TUNE_START,
                TUNE_START + TUNE_SEEDS - 1,
            ],
            "validation_block": [
                VALID_START,
                VALID_START + VALID_SEEDS - 1,
            ],
            "unstable_schema_stress_block": [
                STRESS_START,
                STRESS_START + STRESS_SEEDS - 1,
            ],
            "stage18_stage19_live_artifacts_used": False,
            "tuning_false_alarm_requirement": 0.0,
            "final_false_alarm_ceiling_per_1000": (
                FINAL_FA_CEILING
            ),
        },
        "grid_size": len(STRUCTURAL_GRID),
        "selected_detector": selected,
        "validation": validation_summary,
        "unstable_schema_stress": stress_summary,
    }

    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
