"""Stage 23 live capture: corruption occurs inside the native Open5GS SCP.

The consumer request is sent directly to the instrumented open5gs-scpd process.
No Python response facade or post-SCP mutation sits on the consumer path.
The trusted observation bypasses SCP and queries the native NRF directly.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import random
import re

from .h2_wire import encode
from .stage14_native_scp import (
    NATIVE_NRF,
    NATIVE_SCP,
    NRF_PATH,
    h2_exchange,
)
from .stage5_native import wait_core
from .stage20_structure import serialize_counter, structural_counter
from .stage21_semantic import semantic_projection, serialize_projection

WARMUP_TICKS = 30
EPISODE_TICKS = 12
GAP_TICKS = 4
EPISODES = 6
CYCLE_TICKS = EPISODE_TICKS + GAP_TICKS
TOTAL_TICKS = WARMUP_TICKS + CYCLE_TICKS * EPISODES
MUTATION_LOCAL_TICKS = (0, 4, 8)
EXPECTED_MUTATION_TICKS = tuple(
    WARMUP_TICKS + episode * CYCLE_TICKS + local
    for episode in range(EPISODES)
    for local in MUTATION_LOCAL_TICKS
)

COMPOSE = [
    "docker", "compose",
    "-f", "live/compose.yaml",
    "-f", "live/stage5-compose.yaml",
    "-f", "live/stage14-scp-compose.yaml",
    "-f", "live/stage23-scp-compose.yaml",
]


async def command_output(args: list[str], timeout: int = 30) -> str:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    if proc.returncode:
        raise RuntimeError(
            f"{' '.join(args)} failed: "
            + err.decode(errors="replace")[-1000:]
        )
    return out.decode(errors="replace")


async def compose_output(args: list[str]) -> str:
    return await command_output(COMPOSE + args)


async def await_scp_port() -> None:
    """Wait for the SCP socket without sending an eligible NRF response."""
    last = ""
    for _ in range(60):
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", 7802)
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
            return
        except OSError as ex:
            last = f"{type(ex).__name__}: {ex}"
            await asyncio.sleep(0.35)
    raise RuntimeError("Stage23 native SCP socket not ready: " + last)


def observed_payload(response) -> tuple[dict, dict]:
    if response.status != 200:
        raise AssertionError(f"Expected HTTP 200, got {response.status}")
    obj = json.loads(response.body)
    instances = obj.get("nfInstances")
    if not isinstance(instances, list) or len(instances) < 2:
        raise AssertionError("Native NRF discovery lacks expected NF profiles")
    return obj, {
        "status": response.status,
        "canonical_bytes": len(encode(obj)),
        "nssf_profiles": len(instances),
        "wire_bytes": response.h2_bytes,
        "structure": serialize_counter(structural_counter(obj)),
        "semantic": serialize_projection(semantic_projection(obj)),
    }


def common_path_projection(row: dict) -> dict:
    """Negative control: both observations share the consumer-visible state."""
    output = copy.deepcopy(row)
    for suffix in (
        "status",
        "canonical_bytes",
        "nssf_profiles",
        "wire_bytes",
        "structure",
        "semantic",
    ):
        output[f"trusted_{suffix}"] = output[f"consumer_{suffix}"]
    output["reference_scope"] = "same_native_scp_common_mode"
    return output


def labels_from_native_scp_log(seed: int, log_text: str) -> dict:
    eligible = [
        int(value)
        for value in re.findall(
            r"STAGE23_NATIVE_SCP_LAB_MUTATION eligible=(\d+)",
            log_text,
        )
    ]
    ticks = [value - 1 for value in eligible]
    if tuple(ticks) != EXPECTED_MUTATION_TICKS:
        raise AssertionError(
            "Native SCP in-process audit does not match frozen schedule: "
            f"observed={ticks} expected={list(EXPECTED_MUTATION_TICKS)}"
        )

    episodes = []
    for episode in range(EPISODES):
        start = WARMUP_TICKS + episode * CYCLE_TICKS
        end = start + EPISODE_TICKS
        episodes.append(
            {
                "episode": episode,
                "kind": "native_scp_nfstatus_inprocess",
                "start_tick": start,
                "end_tick": end,
                "mutation_ticks": [
                    start + local for local in MUTATION_LOCAL_TICKS
                ],
            }
        )

    return {
        "stage": 23,
        "seed": seed,
        "warmup_ticks": WARMUP_TICKS,
        "total_ticks": TOTAL_TICKS,
        "episodes": episodes,
        "native_scp_log_mutation_ticks": ticks,
        "native_scp_inprocess_log_marker_count": len(ticks),
        "fault_location": (
            "inside open5gs-scpd src/scp/sbi-path.c response_handler "
            "before ogs_sbi_server_send_response"
        ),
        "external_response_mutator_used": False,
    }


async def capture(seed: int):
    await wait_core(NATIVE_NRF, require_registered=True, timeout=75)
    await await_scp_port()

    rng = random.Random(seed * 230023 + 31)
    telemetry: list[dict] = []
    common_path: list[dict] = []

    for tick in range(TOTAL_TICKS):
        trusted_first = rng.randrange(2) == 0

        async def trusted_reference():
            response = await h2_exchange(NATIVE_NRF, NRF_PATH, timeout=4)
            return observed_payload(response)[1]

        async def consumer_copy():
            response = await h2_exchange(
                NATIVE_SCP,
                NRF_PATH,
                target="http://nrf:80",
                timeout=5,
            )
            return observed_payload(response)[1]

        # Retry a tick only for startup/transport failures. A successful SCP
        # NRF-discovery response advances the native Stage23 eligible counter.
        for attempt in range(4):
            try:
                if trusted_first:
                    trusted = await trusted_reference()
                    consumer = await consumer_copy()
                else:
                    consumer = await consumer_copy()
                    trusted = await trusted_reference()
                break
            except (OSError, ConnectionError, asyncio.TimeoutError):
                if attempt == 3:
                    raise
                await asyncio.sleep(0.25)

        row = {
            "seed": seed,
            "tick": tick,
            "trusted_first": trusted_first,
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
            "reference_scope": "direct_native_nrf_bypasses_native_scp",
        }
        telemetry.append(row)
        common_path.append(common_path_projection(row))

    log_text = await compose_output(["logs", "--no-color", "scp"])
    labels = labels_from_native_scp_log(seed, log_text)

    container_id = (await compose_output(["ps", "-q", "scp"])).strip()
    if not container_id:
        raise AssertionError("Stage23 native SCP container is not running")
    binary_line = (
        await command_output(
            [
                "docker", "exec", container_id, "sha256sum",
                "/opt/open5gs/bin/open5gs-scpd",
            ]
        )
    ).strip()
    binary_sha256 = binary_line.split()[0]
    await command_output(
        [
            "docker", "exec", container_id, "sh", "-c",
            "grep -a -q STAGE23_NATIVE_SCP_LAB_MUTATION "
            "/opt/open5gs/bin/open5gs-scpd",
        ]
    )
    source_sha256 = hashlib.sha256(
        Path("live/stage23-sbi-path.c").read_bytes()
    ).hexdigest()

    provenance = {
        "stage": 23,
        "seed": seed,
        "open5gs_source_ref": "v2.7.6",
        "native_scp_binary_sha256": binary_sha256,
        "instrumented_scp_source_sha256": source_sha256,
        "native_scp_binary_contains_stage23_marker": True,
        "consumer_endpoint": NATIVE_SCP,
        "trusted_endpoint": NATIVE_NRF,
        "consumer_request_sent_directly_to_open5gs_scpd": True,
        "trusted_reference_bypasses_scp": True,
        "python_response_facade_on_consumer_path": False,
        "native_scp_inprocess_marker_count": (
            labels["native_scp_inprocess_log_marker_count"]
        ),
        "semantic_telemetry_contains_raw_scalar_values": False,
        "structural_telemetry_contains_scalar_values": False,
    }
    return telemetry, common_path, labels, provenance, log_text


async def main_async(args):
    telemetry, common_path, labels, provenance, log_text = await capture(
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
    (labels_root / "native_scp_private.log").write_text(
        log_text, encoding="utf8"
    )

    print(
        "STAGE23_CAPTURE_OK "
        f"seed={args.seed} ticks={len(telemetry)} "
        f"inprocess_mutations={labels['native_scp_inprocess_log_marker_count']}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--telemetry-output", default="stage23_telemetry")
    parser.add_argument("--labels-output", default="stage23_private_labels")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
