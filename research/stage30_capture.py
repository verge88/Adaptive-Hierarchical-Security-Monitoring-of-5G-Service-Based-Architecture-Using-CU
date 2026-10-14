"""Stage 30 capture: legitimate NF transitions plus randomized NRF faults.

The Stage-28 native NRF fault injector and randomized attack distribution are
frozen. Attack ticks are shifted by +20 so ticks 30..49 are reserved for
legitimate NSSF transitions with no attack mutations.

Legitimate transition protocol:
- tick 30: graceful nssf2 stop/deregistration -> expected 1/1;
- tick 40: nssf2 start/registration -> expected 2/2;
- tick 45: nssf restart with unchanged logical cardinality -> expected 2/2.

During transition polling the Stage-28 NRF instrumentation is disabled so the
private attack plan's logical discovery-tick counter does not advance.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import re
import secrets

from .stage24_capture import await_scp_port
from .stage28_capture import (
    COMPOSE,
    EPISODES,
    KINDS,
    DURATION_RANGES,
    DENSITY_RANGES,
    GAP_RANGE,
    await_nf_side_readiness,
    build_private_schedule,
    command_output,
    compose_output,
    consumer_counts,
    container_id,
    install_and_enable_plan,
)

WARMUP_TICKS = 30
ATTACK_SHIFT_TICKS = 20
ATTACK_START_TICK = 50
LEGITIMATE_TRANSITION_TICKS = (30, 40, 45)
LEGITIMATE_TRANSITION_WINDOW = tuple(range(30, 50))


def shift_private_schedule(base: dict) -> dict:
    episodes = []
    entries = []
    for episode in base["episodes"]:
        copied = dict(episode)
        copied["start_tick"] = int(episode["start_tick"]) + ATTACK_SHIFT_TICKS
        copied["end_tick"] = int(episode["end_tick"]) + ATTACK_SHIFT_TICKS
        copied["mutation_ticks"] = [
            int(tick) + ATTACK_SHIFT_TICKS
            for tick in episode["mutation_ticks"]
        ]
        episodes.append(copied)

    for entry in base["entries"]:
        entries.append(
            {
                "tick": int(entry["tick"]) + ATTACK_SHIFT_TICKS,
                "kind": entry["kind"],
                "multiplicity": int(entry["multiplicity"]),
            }
        )

    plan_text = "".join(
        f"{entry['tick']}\t{entry['kind']}\t{entry['multiplicity']}\n"
        for entry in entries
    )
    if entries and min(entry["tick"] for entry in entries) < ATTACK_START_TICK:
        raise AssertionError("Stage30 attack schedule leaked into transition window")

    return {
        "episodes": episodes,
        "entries": entries,
        "total_ticks": int(base["total_ticks"]) + ATTACK_SHIFT_TICKS,
        "plan_text": plan_text,
        "plan_sha256": hashlib.sha256(plan_text.encode("utf8")).hexdigest(),
        "plan_nonce": base["plan_nonce"],
    }


def expected_epoch_for_tick(tick: int) -> int:
    if tick < 30:
        return 0
    if tick < 40:
        return 1
    if tick < 45:
        return 2
    return 3


def expected_state_for_tick(tick: int) -> tuple[int, int]:
    epoch = expected_epoch_for_tick(tick)
    if epoch == 1:
        return 1, 1
    return 2, 2


async def set_instrumentation_enabled(nrf_cid: str, enabled: bool) -> None:
    command = (
        "touch /run/stage28/enabled"
        if enabled
        else "rm -f /run/stage28/enabled"
    )
    await command_output(["docker", "exec", nrf_cid, "sh", "-c", command])


async def wait_for_consumer_state(
    expected_count: int,
    expected_registered: int,
    *,
    timeout_s: float = 75.0,
) -> tuple[int, int]:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    last = None
    while loop.time() < deadline:
        try:
            last = await consumer_counts()
            if last == (expected_count, expected_registered):
                return last
        except Exception as ex:  # readiness loop, final error retains context
            last = (type(ex).__name__, str(ex))
        await asyncio.sleep(0.55)
    raise TimeoutError(
        "Stage30 legitimate transition did not settle: "
        f"expected={(expected_count, expected_registered)} last={last}"
    )


async def perform_transition(
    tick: int,
    nrf_cid: str,
    readiness_before: dict[str, str],
) -> dict:
    if tick not in LEGITIMATE_TRANSITION_TICKS:
        raise ValueError(f"Unexpected Stage30 transition tick {tick}")

    await set_instrumentation_enabled(nrf_cid, False)
    before = await consumer_counts()

    if tick == 30:
        action = "authorized_nssf2_deregistration"
        await compose_output(["stop", "-t", "15", "nssf2"])
        expected = (1, 1)
    elif tick == 40:
        action = "authorized_nssf2_registration"
        await compose_output(["start", "nssf2"])
        expected = (2, 2)
    else:
        action = "authorized_nssf1_restart_same_logical_state"
        await compose_output(["restart", "-t", "15", "nssf"])
        expected = (2, 2)

    after = await wait_for_consumer_state(*expected)

    readiness_after = {}
    if expected == (2, 2):
        readiness_after = await await_nf_side_readiness()

    await set_instrumentation_enabled(nrf_cid, True)

    return {
        "tick": tick,
        "action": action,
        "expected_after": list(expected),
        "observed_before": list(before),
        "observed_after": list(after),
        "readiness_before": readiness_before,
        "readiness_after": readiness_after,
    }


def labels_from_native_log(seed: int, log_text: str, schedule: dict) -> dict:
    observed = [
        {
            "tick": int(tick),
            "kind": kind,
            "multiplicity": int(multiplicity),
        }
        for tick, kind, multiplicity in re.findall(
            r"STAGE28_NATIVE_NRF_LAB_MUTATION "
            r"tick=(\d+) "
            r"kind=(phantom_registered|phantom_suspended|status_substitution) "
            r"multiplicity=(\d+)",
            log_text,
        )
    ]
    if observed != schedule["entries"]:
        raise AssertionError(
            "Stage30 native NRF log does not match shifted private plan: "
            f"observed={observed} expected={schedule['entries']}"
        )

    return {
        "stage": 30,
        "seed": seed,
        "warmup_ticks": WARMUP_TICKS,
        "total_ticks": schedule["total_ticks"],
        "episodes": schedule["episodes"],
        "private_plan_entries": schedule["entries"],
        "private_plan_sha256": schedule["plan_sha256"],
        "private_plan_nonce": schedule["plan_nonce"],
        "native_nrf_inprocess_log_marker_count": len(observed),
        "distribution_preregistered_not_realized_schedule": True,
        "attack_schedule_shift_ticks": ATTACK_SHIFT_TICKS,
        "attack_start_tick": ATTACK_START_TICK,
        "legitimate_transition_window": list(LEGITIMATE_TRANSITION_WINDOW),
        "common_source_attack": True,
    }


async def capture(seed: int):
    readiness_ids = await await_nf_side_readiness()
    if len(readiness_ids) != 2:
        raise AssertionError("Stage30 requires two initial live NSSF sources")
    await await_scp_port()

    base_schedule = build_private_schedule()
    schedule = shift_private_schedule(base_schedule)
    nrf_cid = await install_and_enable_plan(schedule["plan_text"])

    raw_rows = []
    transition_events = []
    current_readiness = dict(readiness_ids)

    for tick in range(schedule["total_ticks"]):
        if tick in LEGITIMATE_TRANSITION_TICKS:
            event = await perform_transition(
                tick,
                nrf_cid,
                current_readiness,
            )
            transition_events.append(event)
            if event["readiness_after"]:
                current_readiness = dict(event["readiness_after"])

        witness_first = bool(secrets.randbelow(2))
        consumer_count, consumer_registered = await consumer_counts()

        if tick < ATTACK_START_TICK:
            expected = expected_state_for_tick(tick)
            if (consumer_count, consumer_registered) != expected:
                raise AssertionError(
                    "Stage30 legitimate-transition observation disagrees "
                    f"with preregistered baseline at tick {tick}: "
                    f"observed={(consumer_count, consumer_registered)} "
                    f"expected={expected}"
                )

        witness_count = consumer_count
        witness_registered = consumer_registered

        raw_rows.append(
            {
                "seed": seed,
                "tick": tick,
                "witness_first": witness_first,
                "baseline_epoch": expected_epoch_for_tick(tick),
                "consumer_nssf_count": consumer_count,
                "consumer_registered_count": consumer_registered,
                "compromised_witness_nssf_count": witness_count,
                "compromised_witness_registered_count": witness_registered,
                "common_source_equal": (
                    consumer_count == witness_count
                    and consumer_registered == witness_registered
                ),
            }
        )

    if not all(row["common_source_equal"] for row in raw_rows):
        raise AssertionError("Stage30 common-source mirroring failed")

    nrf_log = await command_output(
        ["docker", "exec", nrf_cid, "cat", "/var/log/open5gs/nrf.log"]
    )
    labels = labels_from_native_log(seed, nrf_log, schedule)

    binary_path = "/src/open5gs/build/src/nrf/open5gs-nrfd"
    binary_line = (
        await command_output(
            ["docker", "exec", nrf_cid, "sha256sum", binary_path]
        )
    ).strip()
    binary_sha256 = binary_line.split()[0]
    await command_output(
        [
            "docker", "exec", nrf_cid, "sh", "-c",
            "grep -a -q STAGE28_NATIVE_NRF_LAB_MUTATION " + binary_path,
        ]
    )
    source_sha256 = hashlib.sha256(
        Path("live/stage28-nnrf-handler.c").read_bytes()
    ).hexdigest()

    if [event["tick"] for event in transition_events] != list(
        LEGITIMATE_TRANSITION_TICKS
    ):
        raise AssertionError("Stage30 legitimate transition sequence incomplete")
    if transition_events[0]["observed_after"] != [1, 1]:
        raise AssertionError("Stage30 deregistration did not reach 1/1")
    if transition_events[1]["observed_after"] != [2, 2]:
        raise AssertionError("Stage30 registration did not restore 2/2")
    if transition_events[2]["observed_after"] != [2, 2]:
        raise AssertionError("Stage30 restart did not restore 2/2")

    provenance = {
        "stage": 30,
        "seed": seed,
        "stage30_role": "held_out_freshness_validation",
        "open5gs_source_ref": "v2.7.6",
        "native_nrf_binary_sha256": binary_sha256,
        "instrumented_nrf_source_sha256": source_sha256,
        "native_nrf_binary_contains_stage28_marker": True,
        "consumer_path": "stock_open5gs_scp_to_instrumented_native_nrf",
        "initial_nf_side_readiness_ids": readiness_ids,
        "final_nf_side_readiness_ids": current_readiness,
        "signed_baseline_available_to_capture_job": False,
        "realized_private_plan_available_to_blind_detector": False,
        "all_common_source_rows_equal": True,
        "attack_generator_frozen_from_stage28": True,
        "detector_rule_frozen_from_stage29": True,
        "attack_schedule_shift_ticks": ATTACK_SHIFT_TICKS,
        "legitimate_transition_ticks": list(LEGITIMATE_TRANSITION_TICKS),
        "legitimate_transition_window": list(LEGITIMATE_TRANSITION_WINDOW),
        "legitimate_transition_events": transition_events,
        "episode_count": EPISODES,
        "distribution": {
            "duration_bins": DURATION_RANGES,
            "density_bins": DENSITY_RANGES,
            "gap_range": GAP_RANGE,
            "attack_kinds": list(KINDS),
            "phantom_multiplicity": [1, 2],
        },
        "private_plan_sha256": schedule["plan_sha256"],
        "native_nrf_inprocess_marker_count": (
            labels["native_nrf_inprocess_log_marker_count"]
        ),
    }
    return raw_rows, labels, provenance, nrf_log


async def main_async(args):
    raw_rows, labels, provenance, nrf_log = await capture(args.seed)

    telemetry_root = Path(args.telemetry_output)
    labels_root = Path(args.labels_output)
    telemetry_root.mkdir(parents=True, exist_ok=True)
    labels_root.mkdir(parents=True, exist_ok=True)

    (telemetry_root / "raw_telemetry.json").write_text(
        json.dumps(raw_rows, indent=2), encoding="utf8"
    )
    (telemetry_root / "provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf8"
    )
    (labels_root / "private_labels.json").write_text(
        json.dumps(labels, indent=2), encoding="utf8"
    )
    (labels_root / "native_nrf_private.log").write_text(
        nrf_log, encoding="utf8"
    )

    print(
        "STAGE30_CAPTURE_OK "
        f"seed={args.seed} ticks={len(raw_rows)} "
        f"transitions={len(provenance['legitimate_transition_events'])} "
        f"attacks={len(labels['episodes'])}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--telemetry-output", default="stage30_raw")
    parser.add_argument("--labels-output", default="stage30_private_labels")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
