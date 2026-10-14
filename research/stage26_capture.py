"""Stage 26: persistent phantom-profile attack inside native NRF.

Stage 25 established NRF-independent inputs for every frozen detector mechanism,
but the original intermittent Stage-24 attacks did not accumulate enough
directional evidence to trigger the frozen Stage-17 channel. Stage 26 keeps the
same external witness projection and changes only the controlled native-NRF
fault family: a phantom NSSF profile is injected persistently for each 12-sample
attack episode.

This is a sensitivity validation for the frozen directional channel, not
retuning. The detector configuration remains unchanged.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import random
import re

from .h2_wire import encode
from .stage14_native_scp import NATIVE_SCP, NRF_PATH, h2_exchange
from .stage24_capture import (
    await_nf_side_witness,
    await_scp_port,
    command_output,
    witness_object,
)
from .stage25_capture import (
    common_path_projection,
    projected_fields,
    witness_supported_projection,
)

WARMUP_TICKS = 30
EPISODE_TICKS = 12
GAP_TICKS = 4
EPISODES = 6
CYCLE_TICKS = EPISODE_TICKS + GAP_TICKS
TOTAL_TICKS = WARMUP_TICKS + EPISODES * CYCLE_TICKS
ATTACK_KIND = "phantom_profile_persistent"
PHANTOM_ID = "26000000-0000-4000-8000-000000000026"

COMPOSE = [
    "docker", "compose",
    "-f", "live/compose.yaml",
    "-f", "live/stage5-compose.yaml",
    "-f", "live/stage14-scp-compose.yaml",
    "-f", "live/stage26-nrf-compose.yaml",
]


async def compose_output(args: list[str]) -> str:
    return await command_output(COMPOSE + args)


async def container_id(service: str) -> str:
    value = (await compose_output(["ps", "-q", service])).strip()
    if not value:
        raise RuntimeError(f"Container for {service} is not running")
    return value


async def enable_native_nrf_instrumentation() -> str:
    cid = await container_id("nrf")
    await command_output(
        [
            "docker", "exec", cid, "sh", "-c",
            "mkdir -p /run/stage26 && rm -f /run/stage26/enabled "
            "&& touch /run/stage26/enabled",
        ]
    )
    return cid


def expected_episodes() -> list[dict]:
    output = []
    for episode in range(EPISODES):
        start = WARMUP_TICKS + episode * CYCLE_TICKS
        output.append(
            {
                "episode": episode,
                "kind": ATTACK_KIND,
                "start_tick": start,
                "end_tick": start + EPISODE_TICKS,
                "mutation_ticks": list(
                    range(start, start + EPISODE_TICKS)
                ),
            }
        )
    return output


def labels_from_native_nrf_log(seed: int, log_text: str) -> dict:
    observed = [
        int(value) - 1
        for value in re.findall(
            r"STAGE26_NATIVE_NRF_LAB_MUTATION "
            r"eligible=(\d+) kind=phantom_profile_persistent",
            log_text,
        )
    ]
    expected = [
        tick
        for episode in expected_episodes()
        for tick in episode["mutation_ticks"]
    ]
    if observed != expected:
        raise AssertionError(
            "Stage26 native NRF audit does not match frozen schedule: "
            f"observed={observed} expected={expected}"
        )
    return {
        "stage": 26,
        "seed": seed,
        "warmup_ticks": WARMUP_TICKS,
        "total_ticks": TOTAL_TICKS,
        "episodes": expected_episodes(),
        "native_nrf_log_mutation_ticks": observed,
        "native_nrf_inprocess_log_marker_count": len(observed),
        "fault_location": (
            "inside open5gs-nrfd src/nrf/nnrf-handler.c "
            "nrf_nnrf_handle_nf_discover before stock server send"
        ),
        "internal_nrf_registry_modified": False,
        "phantom_nf_instance_id": PHANTOM_ID,
    }


async def capture(seed: int):
    registration_ids = await await_nf_side_witness()
    await await_scp_port()
    nrf_cid = await enable_native_nrf_instrumentation()

    known_registration_ids = {
        value.lower() for value in registration_ids.values()
    }
    if PHANTOM_ID in known_registration_ids:
        raise AssertionError("Stage26 phantom UUID unexpectedly belongs to a real NSSF")

    rng = random.Random(seed * 260026 + 43)
    telemetry = []
    common_path = []
    warmup_exact = 0

    for tick in range(TOTAL_TICKS):
        witness_first = rng.randrange(2) == 0

        async def trusted_witness():
            obj = await witness_object(registration_ids)
            projected = witness_supported_projection(
                obj, known_registration_ids
            )
            return projected_fields(
                projected,
                wire_bytes=len(encode(projected)),
                known_registration_ids=known_registration_ids,
            )

        async def consumer_copy():
            response = await h2_exchange(
                NATIVE_SCP,
                NRF_PATH,
                target="http://nrf:80",
                timeout=5,
            )
            if response.status != 200:
                raise AssertionError(
                    f"Compromised NRF discovery returned HTTP {response.status}"
                )
            obj = json.loads(response.body)
            return projected_fields(
                obj,
                wire_bytes=response.h2_bytes,
                known_registration_ids=known_registration_ids,
            )

        if witness_first:
            trusted = await trusted_witness()
            consumer = await consumer_copy()
        else:
            consumer = await consumer_copy()
            trusted = await trusted_witness()

        row = {
            "seed": seed,
            "tick": tick,
            "trusted_first": witness_first,
            "trusted_status": trusted["status"],
            "consumer_status": consumer["status"],
            "trusted_canonical_bytes": trusted["canonical_bytes"],
            "consumer_canonical_bytes": consumer["canonical_bytes"],
            "trusted_nssf_profiles": trusted["nssf_profiles"],
            "consumer_nssf_profiles": consumer["nssf_profiles"],
            "trusted_wire_bytes": trusted["wire_bytes"],
            "consumer_wire_bytes": consumer["wire_bytes"],
            "trusted_structure": trusted["structure"],
            "consumer_structure": consumer["structure"],
            "trusted_semantic": trusted["semantic"],
            "consumer_semantic": consumer["semantic"],
            "reference_scope": (
                "stage26_nf_side_projection_outside_nrf"
            ),
        }
        telemetry.append(row)
        common_path.append(common_path_projection(row))

        if tick < WARMUP_TICKS:
            exact = (
                row["trusted_canonical_bytes"]
                == row["consumer_canonical_bytes"]
                and row["trusted_nssf_profiles"]
                == row["consumer_nssf_profiles"]
                and row["trusted_structure"]
                == row["consumer_structure"]
                and row["trusted_semantic"]
                == row["consumer_semantic"]
            )
            warmup_exact += int(exact)
            if not exact:
                raise AssertionError(
                    "Stage26 projected warm-up is not exactly paired"
                )

    nrf_log = await command_output(
        ["docker", "exec", nrf_cid, "cat", "/var/log/open5gs/nrf.log"]
    )
    labels = labels_from_native_nrf_log(seed, nrf_log)

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
            "grep -a -q STAGE26_NATIVE_NRF_LAB_MUTATION " + binary_path,
        ]
    )
    source_sha256 = hashlib.sha256(
        Path("live/stage26-nnrf-handler.c").read_bytes()
    ).hexdigest()

    provenance = {
        "stage": 26,
        "seed": seed,
        "open5gs_source_ref": "v2.7.6",
        "native_nrf_binary_sha256": binary_sha256,
        "instrumented_nrf_source_sha256": source_sha256,
        "native_nrf_binary_contains_stage26_marker": True,
        "consumer_path": "stock_open5gs_scp_to_instrumented_native_nrf",
        "trusted_reference_reads_nrf_discovery": False,
        "trusted_reference_uses_nf_local_registration_logs": True,
        "trusted_reference_uses_direct_nf_liveness": True,
        "same_projection_applied_to_trusted_and_consumer": True,
        "directional_numeric_reference_independent_of_nrf": True,
        "attack_family": ATTACK_KIND,
        "persistent_attack_samples_per_episode": EPISODE_TICKS,
        "warmup_exact_pair_fraction": warmup_exact / WARMUP_TICKS,
        "native_nrf_inprocess_marker_count": (
            labels["native_nrf_inprocess_log_marker_count"]
        ),
    }
    return telemetry, common_path, labels, provenance, nrf_log


async def main_async(args):
    telemetry, common_path, labels, provenance, nrf_log = await capture(
        args.seed
    )

    telemetry_root = Path(args.telemetry_output)
    labels_root = Path(args.labels_output)
    telemetry_root.mkdir(parents=True, exist_ok=True)
    labels_root.mkdir(parents=True, exist_ok=True)

    (telemetry_root / "telemetry.json").write_text(
        json.dumps(telemetry, indent=2), encoding="utf8"
    )
    (telemetry_root / "common_path_telemetry.json").write_text(
        json.dumps(common_path, indent=2), encoding="utf8"
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
        "STAGE26_CAPTURE_OK "
        f"seed={args.seed} ticks={len(telemetry)} "
        f"mutations={labels['native_nrf_inprocess_log_marker_count']} "
        f"warmup_exact={provenance['warmup_exact_pair_fraction']:.3f}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--telemetry-output", default="stage26_telemetry")
    parser.add_argument("--labels-output", default="stage26_private_labels")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
