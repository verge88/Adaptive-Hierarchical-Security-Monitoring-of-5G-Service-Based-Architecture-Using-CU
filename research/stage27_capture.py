"""Stage 27 raw capture for NRF + witness common-source compromise.

The native Open5GS NRF reuses the Stage-26 persistent phantom-profile
instrumentation. The ordinary NF-side witness is then deliberately compromised
at the software observation layer: it reports the same false NSSF cardinality
and REGISTERED-state count as the consumer-visible NRF response.

The signed attestation baseline is NOT available in this capture job. It is
introduced later by an independent GitHub Actions authority/verifier path.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import random

from .stage14_native_scp import NATIVE_SCP, NRF_PATH, h2_exchange
from .stage24_capture import await_nf_side_witness, await_scp_port, command_output
from .stage26_capture import (
    COMPOSE,
    TOTAL_TICKS,
    WARMUP_TICKS,
    container_id,
    enable_native_nrf_instrumentation,
    labels_from_native_nrf_log,
)


async def consumer_counts() -> tuple[int, int]:
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
    instances = obj.get("nfInstances")
    if not isinstance(instances, list):
        raise AssertionError("NRF discovery lacks nfInstances")

    nssf = [
        item
        for item in instances
        if isinstance(item, dict) and item.get("nfType") == "NSSF"
    ]
    registered = [
        item
        for item in nssf
        if item.get("nfStatus") == "REGISTERED"
    ]
    return len(nssf), len(registered)


async def capture(seed: int):
    # Pre-compromise readiness only. These local NF facts are not used as the
    # Stage-27 trusted reference during the attack.
    preattack_ids = await await_nf_side_witness()
    if len(preattack_ids) != 2:
        raise AssertionError("Stage27 requires exactly two live NSSF sources")

    await await_scp_port()
    nrf_cid = await enable_native_nrf_instrumentation()

    rng = random.Random(seed * 270027 + 47)
    raw_rows = []

    for tick in range(TOTAL_TICKS):
        # Randomized ordering is retained as a protocol marker even though the
        # compromised witness intentionally mirrors the false consumer state.
        witness_first = rng.randrange(2) == 0
        consumer_count, consumer_registered = await consumer_counts()

        # Controlled simultaneous witness compromise: the witness software
        # colludes with the NRF and returns exactly the same false state.
        witness_count = consumer_count
        witness_registered = consumer_registered

        raw_rows.append(
            {
                "seed": seed,
                "tick": tick,
                "witness_first": witness_first,
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
        raise AssertionError("Stage27 common-source compromise did not align")

    nrf_log = await command_output(
        ["docker", "exec", nrf_cid, "cat", "/var/log/open5gs/nrf.log"]
    )
    labels = labels_from_native_nrf_log(seed, nrf_log)
    labels["stage"] = 27
    labels["common_source_attack"] = True
    labels["compromised_components"] = [
        "native_open5gs_nrf_discovery_response",
        "nf_side_witness_software_output",
    ]

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

    clean_rows = raw_rows[:WARMUP_TICKS]
    if not all(
        row["consumer_nssf_count"] == 2
        and row["consumer_registered_count"] == 2
        for row in clean_rows
    ):
        raise AssertionError("Stage27 clean warm-up baseline is not 2/2")

    provenance = {
        "stage": 27,
        "seed": seed,
        "open5gs_source_ref": "v2.7.6",
        "native_nrf_binary_sha256": binary_sha256,
        "instrumented_nrf_source_sha256": source_sha256,
        "native_nrf_binary_contains_stage26_marker": True,
        "consumer_path": "stock_open5gs_scp_to_instrumented_native_nrf",
        "preattack_nf_side_readiness_ids": preattack_ids,
        "preattack_readiness_used_as_detector_reference": False,
        "witness_compromise_model": (
            "software witness returns the same NSSF cardinality and "
            "REGISTERED count as the compromised NRF consumer view"
        ),
        "signed_attestation_available_to_capture_job": False,
        "all_common_source_rows_equal": True,
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
        "STAGE27_CAPTURE_OK "
        f"seed={args.seed} ticks={len(raw_rows)} "
        f"common_source_equal={provenance['all_common_source_rows_equal']}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--telemetry-output", default="stage27_raw")
    parser.add_argument("--labels-output", default="stage27_private_labels")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
