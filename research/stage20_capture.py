"""Stage 20 live telemetry capture with value-free structural fingerprints.

The private fault schedule remains isolated in the capture process. Detector
jobs receive telemetry only. Structural telemetry contains typed JSON paths and
multiplicities, never scalar values or attack labels.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import random

from .h2_wire import encode, h2_request
from .stage14_native_scp import (
    NATIVE_SCP,
    NRF_PATH,
    await_scp_ready,
    discovered_nssf_ids,
    h2_exchange,
)
from .stage5_native import wait_core
from .stage18_gateway import BlindPostSCPGateway, TOTAL_TICKS
from .stage20_structure import (
    serialize_counter,
    structural_counter,
)


async def capture(seed: int):
    await wait_core(
        "http://127.0.0.1:7777",
        require_registered=True,
        timeout=75,
    )
    await await_scp_ready()

    gateway = await BlindPostSCPGateway(seed).start()
    gateway_url = f"http://127.0.0.1:{gateway.server.port}"
    order_rng = random.Random(seed * 202020 + 73)
    telemetry = []

    try:
        for tick in range(TOTAL_TICKS):
            trusted_first = order_rng.randrange(2) == 0

            async def trusted_reference():
                response = await h2_exchange(
                    NATIVE_SCP,
                    NRF_PATH,
                    target="http://nrf:80",
                    timeout=4,
                )
                ids = discovered_nssf_ids(response)
                obj = json.loads(response.body)
                return {
                    "status": response.status,
                    "object": obj,
                    "canonical_bytes": len(encode(obj)),
                    "nssf_profiles": len(ids),
                    "wire_bytes": response.h2_bytes,
                    "elapsed_ms": round(
                        response.duration_s * 1000,
                        3,
                    ),
                    "structure": serialize_counter(
                        structural_counter(obj)
                    ),
                }

            async def consumer_copy():
                status, obj, wire, headers = await h2_request(
                    gateway_url,
                    "/stage18/nrf",
                    "GET",
                    timeout=5,
                )
                if status != 200:
                    raise AssertionError(
                        f"Stage20 gateway returned HTTP {status}"
                    )
                instances = obj.get("nfInstances")
                return {
                    "status": status,
                    "object": obj,
                    "canonical_bytes": len(encode(obj)),
                    "nssf_profiles": (
                        len(instances)
                        if isinstance(instances, list)
                        else -1
                    ),
                    "wire_bytes": wire,
                    "structure": serialize_counter(
                        structural_counter(obj)
                    ),
                }

            if trusted_first:
                trusted = await trusted_reference()
                consumer = await consumer_copy()
            else:
                consumer = await consumer_copy()
                trusted = await trusted_reference()

            telemetry.append(
                {
                    "seed": seed,
                    "tick": tick,
                    "trusted_first": trusted_first,
                    "trusted_status": trusted["status"],
                    "consumer_status": consumer["status"],
                    "trusted_canonical_bytes": trusted[
                        "canonical_bytes"
                    ],
                    "consumer_canonical_bytes": consumer[
                        "canonical_bytes"
                    ],
                    "trusted_nssf_profiles": trusted[
                        "nssf_profiles"
                    ],
                    "consumer_nssf_profiles": consumer[
                        "nssf_profiles"
                    ],
                    "trusted_wire_bytes": trusted["wire_bytes"],
                    "consumer_wire_bytes": consumer["wire_bytes"],
                    "trusted_elapsed_ms": trusted["elapsed_ms"],
                    "trusted_structure": trusted["structure"],
                    "consumer_structure": consumer["structure"],
                }
            )
    finally:
        await gateway.close()

    if len(telemetry) != TOTAL_TICKS:
        raise AssertionError("Incomplete Stage20 telemetry")
    if gateway.tick != TOTAL_TICKS:
        raise AssertionError("Stage20 gateway call count mismatch")

    provenance = gateway.public_provenance()
    if (
        not provenance["all_native_scp_upstream_http_200"]
        or provenance[
            "min_native_nssf_profiles_seen_upstream"
        ] < 2
    ):
        raise AssertionError(
            "Stage20 did not preserve genuine native SCP/NRF route"
        )
    provenance["structural_telemetry_contains_scalar_values"] = False

    labels = gateway.private_labels()
    labels["stage"] = 20

    return telemetry, labels, provenance


async def main_async(args):
    telemetry, labels, provenance = await capture(args.seed)

    telemetry_root = Path(args.telemetry_output)
    labels_root = Path(args.labels_output)
    telemetry_root.mkdir(parents=True, exist_ok=True)
    labels_root.mkdir(parents=True, exist_ok=True)

    (telemetry_root / "telemetry.json").write_text(
        json.dumps(telemetry, indent=2),
        encoding="utf8",
    )
    (telemetry_root / "provenance.json").write_text(
        json.dumps(provenance, indent=2),
        encoding="utf8",
    )
    (labels_root / "private_labels.json").write_text(
        json.dumps(labels, indent=2),
        encoding="utf8",
    )

    print(
        "STAGE20_CAPTURE_OK "
        f"seed={args.seed} ticks={len(telemetry)} "
        f"native_scp_calls={provenance['native_scp_upstream_calls']}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument(
        "--telemetry-output",
        default="stage20_telemetry",
    )
    parser.add_argument(
        "--labels-output",
        default="stage20_private_labels",
    )
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
