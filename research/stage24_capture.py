"""Stage 24 live capture: compromised native NRF with an external NF-side witness.

The consumer view traverses the stock Open5GS SCP to an instrumented native
Open5GS NRF. The NRF alters selected NF Discovery responses inside its own
process. The trusted semantic witness is built without reading NRF discovery
responses: it uses each NSSF's own local "NF registered" log record together
with a direct HTTP/2 liveness probe to that NSSF.

Only the semantic reference is independently reconstructed. Numeric byte and
structural channels are deliberately neutralized by assigning their trusted
fields to the same consumer-visible values. Therefore a positive Stage-24
result is evidence for the frozen Stage-21 semantic channel under an external
NRF-independent witness, not a claim that every Stage-21 channel has an
independent NRF witness.
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
from .stage5_native import NFS, native_h2_status
from .stage20_structure import serialize_counter, structural_counter
from .stage21_semantic import semantic_projection, serialize_projection

WARMUP_TICKS = 30
EPISODE_TICKS = 12
GAP_TICKS = 4
EPISODES = 6
CYCLE_TICKS = EPISODE_TICKS + GAP_TICKS
TOTAL_TICKS = WARMUP_TICKS + CYCLE_TICKS * EPISODES
MUTATION_LOCAL_TICKS = (0, 4, 8)
NSSF_WITNESS = tuple(nf for nf in NFS if nf.kind == "NSSF")

COMPOSE = [
    "docker", "compose",
    "-f", "live/compose.yaml",
    "-f", "live/stage5-compose.yaml",
    "-f", "live/stage14-scp-compose.yaml",
    "-f", "live/stage24-nrf-compose.yaml",
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
            + err.decode(errors="replace")[-1200:]
        )
    return out.decode(errors="replace")


async def compose_output(args: list[str]) -> str:
    return await command_output(COMPOSE + args)


async def container_id(service: str) -> str:
    value = (await compose_output(["ps", "-q", service])).strip()
    if not value:
        raise RuntimeError(f"Container for {service} is not running")
    return value


async def container_log(service: str, path: str) -> str:
    cid = await container_id(service)
    return await command_output(["docker", "exec", cid, "cat", path])


def latest_nf_registration_id(log_text: str) -> str:
    matches = re.findall(
        r"\[([0-9A-Fa-f-]{36})\]\s+NF registered \[Heartbeat:\d+s\]",
        log_text,
    )
    if not matches:
        raise ValueError("No NF-side registered-state marker found")
    return matches[-1].lower()


async def await_scp_port() -> None:
    last = ""
    for _ in range(80):
        try:
            _reader, writer = await asyncio.open_connection("127.0.0.1", 7802)
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
            return
        except OSError as ex:
            last = f"{type(ex).__name__}: {ex}"
            await asyncio.sleep(0.35)
    raise RuntimeError("Stock SCP socket not ready: " + last)


async def await_nf_side_witness(timeout_s: float = 75.0) -> dict[str, str]:
    """Wait only on NSSF-local evidence; do not query NRF discovery."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    last = ""
    while loop.time() < deadline:
        try:
            statuses = await asyncio.gather(
                *(native_h2_status(nf) for nf in NSSF_WITNESS)
            )
            if not all(row["reachable"] for row in statuses):
                last = f"unreachable NSSF: {statuses}"
                await asyncio.sleep(0.45)
                continue

            output = {}
            for nf in NSSF_WITNESS:
                log_text = await container_log(
                    nf.service, "/var/log/open5gs/nssf.log"
                )
                output[nf.service] = latest_nf_registration_id(log_text)
            if len(set(output.values())) != len(NSSF_WITNESS):
                raise AssertionError("NF-side witness IDs are not unique")
            return output
        except (RuntimeError, ValueError, OSError) as ex:
            last = f"{type(ex).__name__}: {ex}"
            await asyncio.sleep(0.45)

    raise TimeoutError("NF-side witness readiness failed: " + last)


async def enable_native_nrf_instrumentation() -> str:
    cid = await container_id("nrf")
    await command_output(
        [
            "docker", "exec", cid, "sh", "-c",
            "mkdir -p /run/stage24 && rm -f /run/stage24/enabled "
            "&& touch /run/stage24/enabled",
        ]
    )
    return cid


async def witness_object(registration_ids: dict[str, str]) -> dict:
    statuses = await asyncio.gather(
        *(native_h2_status(nf) for nf in NSSF_WITNESS)
    )
    if not all(item["reachable"] for item in statuses):
        raise AssertionError(
            "NF-side witness lost direct NSSF reachability during capture"
        )

    profiles = []
    for nf in NSSF_WITNESS:
        profiles.append(
            {
                "nfInstanceId": registration_ids[nf.service],
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
            }
        )
    profiles.sort(key=lambda item: item["nfInstanceId"])
    return {"nfInstances": profiles}


def consumer_fields(response) -> tuple[dict, dict]:
    if response.status != 200:
        raise AssertionError(
            f"Compromised NRF discovery returned HTTP {response.status}"
        )
    obj = json.loads(response.body)
    instances = obj.get("nfInstances")
    if not isinstance(instances, list):
        raise AssertionError("NRF discovery response lacks nfInstances")
    return obj, {
        "status": response.status,
        "canonical_bytes": len(encode(obj)),
        "nssf_profiles": len(
            [
                item
                for item in instances
                if isinstance(item, dict)
                and item.get("nfType") == "NSSF"
            ]
        ),
        "wire_bytes": response.h2_bytes,
        "structure": serialize_counter(structural_counter(obj)),
        "semantic": serialize_projection(semantic_projection(obj)),
    }


def common_path_projection(row: dict) -> dict:
    output = dict(row)
    output["trusted_semantic"] = output["consumer_semantic"]
    output["reference_scope"] = "same_compromised_nrf_common_mode"
    return output


def expected_episodes() -> list[dict]:
    episodes = []
    for episode in range(EPISODES):
        start = WARMUP_TICKS + episode * CYCLE_TICKS
        kind = (
            "status_substitution"
            if episode % 2 == 0
            else "profile_drop"
        )
        episodes.append(
            {
                "episode": episode,
                "kind": kind,
                "start_tick": start,
                "end_tick": start + EPISODE_TICKS,
                "mutation_ticks": [
                    start + local for local in MUTATION_LOCAL_TICKS
                ],
            }
        )
    return episodes


def labels_from_native_nrf_log(seed: int, log_text: str) -> dict:
    observed = [
        (int(eligible) - 1, kind)
        for eligible, kind in re.findall(
            r"STAGE24_NATIVE_NRF_LAB_MUTATION "
            r"eligible=(\d+) kind=(status_substitution|profile_drop)",
            log_text,
        )
    ]
    expected = [
        (tick, episode["kind"])
        for episode in expected_episodes()
        for tick in episode["mutation_ticks"]
    ]
    if observed != expected:
        raise AssertionError(
            "Native NRF in-process audit does not match frozen schedule: "
            f"observed={observed} expected={expected}"
        )

    return {
        "stage": 24,
        "seed": seed,
        "warmup_ticks": WARMUP_TICKS,
        "total_ticks": TOTAL_TICKS,
        "episodes": expected_episodes(),
        "native_nrf_log_mutations": [
            {"tick": tick, "kind": kind}
            for tick, kind in observed
        ],
        "native_nrf_inprocess_log_marker_count": len(observed),
        "fault_location": (
            "inside open5gs-nrfd src/nrf/nnrf-handler.c "
            "nrf_nnrf_handle_nf_discover before stock server send"
        ),
        "internal_nrf_registry_modified": False,
    }


async def capture(seed: int):
    registration_ids = await await_nf_side_witness()
    await await_scp_port()
    nrf_cid = await enable_native_nrf_instrumentation()

    rng = random.Random(seed * 240024 + 37)
    telemetry = []
    common_path = []

    for tick in range(TOTAL_TICKS):
        witness_first = rng.randrange(2) == 0

        async def trusted_witness():
            obj = await witness_object(registration_ids)
            return {
                "semantic": serialize_projection(
                    semantic_projection(obj)
                ),
                "nssf_profiles": len(obj["nfInstances"]),
            }

        async def consumer_copy():
            response = await h2_exchange(
                NATIVE_SCP,
                NRF_PATH,
                target="http://nrf:80",
                timeout=5,
            )
            return consumer_fields(response)[1]

        if witness_first:
            trusted = await trusted_witness()
            consumer = await consumer_copy()
        else:
            consumer = await consumer_copy()
            trusted = await trusted_witness()

        # Numeric and structural channels are intentionally neutralized.
        # The only independent Stage-24 reference is the NF-side semantic
        # witness. This keeps the frozen detector unchanged while preventing
        # unsupported pseudo-independence claims for byte/structure signals.
        row = {
            "seed": seed,
            "tick": tick,
            "trusted_first": witness_first,
            "trusted_status": consumer["status"],
            "consumer_status": consumer["status"],
            "trusted_canonical_bytes": consumer["canonical_bytes"],
            "consumer_canonical_bytes": consumer["canonical_bytes"],
            "trusted_nssf_profiles": trusted["nssf_profiles"],
            "consumer_nssf_profiles": consumer["nssf_profiles"],
            "trusted_wire_bytes": consumer["wire_bytes"],
            "consumer_wire_bytes": consumer["wire_bytes"],
            "trusted_structure": consumer["structure"],
            "consumer_structure": consumer["structure"],
            "trusted_semantic": trusted["semantic"],
            "consumer_semantic": consumer["semantic"],
            "reference_scope": (
                "nssf_local_registration_logs_plus_direct_nf_liveness"
            ),
        }
        telemetry.append(row)
        common_path.append(common_path_projection(row))

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
            "grep -a -q STAGE24_NATIVE_NRF_LAB_MUTATION "
            + binary_path,
        ]
    )
    source_sha256 = hashlib.sha256(
        Path("live/stage24-nnrf-handler.c").read_bytes()
    ).hexdigest()

    provenance = {
        "stage": 24,
        "seed": seed,
        "open5gs_source_ref": "v2.7.6",
        "native_nrf_binary_sha256": binary_sha256,
        "instrumented_nrf_source_sha256": source_sha256,
        "native_nrf_binary_contains_stage24_marker": True,
        "consumer_path": "stock_open5gs_scp_to_instrumented_native_nrf",
        "consumer_request_uses_stock_open5gs_scp": True,
        "python_response_facade_on_consumer_path": False,
        "trusted_reference_reads_nrf_discovery": False,
        "trusted_reference_uses_nf_local_registration_logs": True,
        "trusted_reference_uses_direct_nf_liveness": True,
        "witness_registration_ids": registration_ids,
        "numeric_channel_neutralized": True,
        "structural_channel_neutralized": True,
        "semantic_channel_has_external_nrf_independent_witness": True,
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
        "STAGE24_CAPTURE_OK "
        f"seed={args.seed} ticks={len(telemetry)} "
        f"inprocess_mutations="
        f"{labels['native_nrf_inprocess_log_marker_count']} "
        f"witness_ids={len(provenance['witness_registration_ids'])}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--telemetry-output", default="stage24_telemetry")
    parser.add_argument("--labels-output", default="stage24_private_labels")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
