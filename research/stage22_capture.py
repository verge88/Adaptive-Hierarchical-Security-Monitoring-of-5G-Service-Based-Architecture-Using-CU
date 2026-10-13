"""Stage 22 live capture for an SCP-compromise trust-boundary experiment."""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
from pathlib import Path
import random

from .h2_wire import encode, h2_request
from .stage14_native_scp import (
    NATIVE_NRF,
    NRF_PATH,
    await_scp_ready,
    discovered_nssf_ids,
    h2_exchange,
)
from .stage5_native import wait_core
from .stage20_structure import serialize_counter, structural_counter
from .stage21_semantic import semantic_projection, serialize_projection
from .stage22_scp_fault import (
    Stage22CompromisedSCPFacade,
    TOTAL_TICKS,
)


def common_path_projection(row: dict) -> dict:
    """Construct the common-mode control visible below one compromised SCP.

    This control intentionally copies the consumer view into the nominal
    reference fields.  It represents the information-theoretic case where both
    observations are downstream of the same compromised component and therefore
    receive the same false state.
    """
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
    output["reference_scope"] = "same_compromised_scp_common_mode"
    return output


async def capture(seed: int):
    await wait_core(
        NATIVE_NRF,
        require_registered=True,
        timeout=75,
    )
    await await_scp_ready()

    facade = await Stage22CompromisedSCPFacade(seed).start()
    facade_url = f"http://127.0.0.1:{facade.server.port}"
    order_rng = random.Random(seed * 222227 + 229)

    telemetry = []
    common_path = []

    try:
        for tick in range(TOTAL_TICKS):
            trusted_first = order_rng.randrange(2) == 0

            async def trusted_reference():
                # Critical Stage-22 change: bypass the possibly compromised SCP.
                response = await h2_exchange(
                    NATIVE_NRF,
                    NRF_PATH,
                    timeout=4,
                )
                ids = discovered_nssf_ids(response)
                obj = json.loads(response.body)
                return {
                    "status": response.status,
                    "canonical_bytes": len(encode(obj)),
                    "nssf_profiles": len(ids),
                    "wire_bytes": response.h2_bytes,
                    "elapsed_ms": round(
                        response.duration_s * 1000, 3
                    ),
                    "structure": serialize_counter(
                        structural_counter(obj)
                    ),
                    "semantic": serialize_projection(
                        semantic_projection(obj)
                    ),
                }

            async def consumer_copy():
                status, obj, wire, _headers = await h2_request(
                    facade_url,
                    "/stage22/scp-nrf",
                    "GET",
                    timeout=5,
                )
                if status != 200:
                    raise AssertionError(
                        f"Stage22 SCP facade returned HTTP {status}"
                    )
                instances = obj.get("nfInstances")
                return {
                    "status": status,
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
                    "semantic": serialize_projection(
                        semantic_projection(obj)
                    ),
                }

            if trusted_first:
                trusted = await trusted_reference()
                consumer = await consumer_copy()
            else:
                consumer = await consumer_copy()
                trusted = await trusted_reference()

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
                "trusted_elapsed_ms": trusted["elapsed_ms"],
                "trusted_structure": trusted["structure"],
                "consumer_structure": consumer["structure"],
                "trusted_semantic": trusted["semantic"],
                "consumer_semantic": consumer["semantic"],
                "reference_scope": "direct_native_nrf_bypasses_scp",
            }
            telemetry.append(row)
            common_path.append(common_path_projection(row))
    finally:
        await facade.close()

    if len(telemetry) != TOTAL_TICKS:
        raise AssertionError("Incomplete Stage22 telemetry")
    if facade.tick != TOTAL_TICKS:
        raise AssertionError("Stage22 facade call count mismatch")

    provenance = facade.public_provenance()
    provenance.update(
        {
            "trusted_reference_bypasses_scp": True,
            "trusted_reference_is_native_nrf": True,
            "common_path_control_is_derived_label_free": True,
            "semantic_telemetry_contains_raw_scalar_values": False,
            "structural_telemetry_contains_scalar_values": False,
        }
    )
    if (
        not provenance["all_native_scp_upstream_http_200"]
        or provenance["min_native_nssf_profiles_seen_upstream"] < 2
    ):
        raise AssertionError(
            "Stage22 did not preserve genuine native SCP->NRF forwarding"
        )

    return (
        telemetry,
        common_path,
        facade.private_labels(),
        provenance,
    )


async def main_async(args):
    telemetry, common_path, labels, provenance = await capture(args.seed)

    telemetry_root = Path(args.telemetry_output)
    labels_root = Path(args.labels_output)
    telemetry_root.mkdir(parents=True, exist_ok=True)
    labels_root.mkdir(parents=True, exist_ok=True)

    (telemetry_root / "telemetry.json").write_text(
        json.dumps(telemetry, indent=2),
        encoding="utf8",
    )
    (telemetry_root / "common_path_telemetry.json").write_text(
        json.dumps(common_path, indent=2),
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
        "STAGE22_CAPTURE_OK "
        f"seed={args.seed} ticks={len(telemetry)} "
        f"native_scp_calls={provenance['native_scp_upstream_calls']} "
        "reference=direct_nrf_bypass_scp",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument(
        "--telemetry-output",
        default="stage22_telemetry",
    )
    parser.add_argument(
        "--labels-output",
        default="stage22_private_labels",
    )
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
