"""Stage 25: full multichannel NRF-independent witness projection.

Stage 24 proved semantic detection of false NF Discovery data generated inside
the native Open5GS NRF. Numeric and structural channels were deliberately
neutralized because the minimal NF-side witness did not reproduce the full NRF
Discovery document.

Stage 25 closes that narrower gap by applying the same witness-supported
projection to BOTH observations before the frozen Stage-21 detector sees them.
Only facts independently justified outside NRF are retained:
nfInstanceId, nfType and nfStatus for the two NSSF processes.

This yields an NRF-independent reference for:
- directional canonical-byte discrepancy;
- sparse directional memory;
- structural fingerprinting;
- semantic value comparison.

No detector thresholds are retuned and the native NRF fault implementation is
unchanged from Stage 24.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import random

from .h2_wire import encode
from .stage14_native_scp import NATIVE_SCP, NRF_PATH, h2_exchange
from .stage20_structure import serialize_counter, structural_counter
from .stage21_semantic import semantic_projection, serialize_projection
from .stage24_capture import (
    COMPOSE,
    EPISODES,
    TOTAL_TICKS,
    WARMUP_TICKS,
    await_nf_side_witness,
    await_scp_port,
    command_output,
    compose_output,
    container_id,
    enable_native_nrf_instrumentation,
    labels_from_native_nrf_log,
    witness_object,
)


def witness_supported_projection(
    obj: dict,
    known_registration_ids: set[str] | None = None,
) -> dict:
    """Project onto independently attestable NSSF facts.

    nfRegisteredAtSource is derived from the NF-side registration UUID set.
    It is intentionally included as an explicit witness-backed field so the
    structural representation records membership evidence per returned profile.
    """
    instances = obj.get("nfInstances")
    if not isinstance(instances, list):
        raise AssertionError("Projected object lacks nfInstances")

    output = []
    for item in instances:
        if not isinstance(item, dict) or item.get("nfType") != "NSSF":
            continue
        nf_id = item.get("nfInstanceId")
        status = item.get("nfStatus")
        if not isinstance(nf_id, str) or not isinstance(status, str):
            raise AssertionError(
                "NSSF profile lacks witness-supported identity/status"
            )
        normalized_id = nf_id.lower()
        output.append(
            {
                "nfInstanceId": normalized_id,
                "nfType": "NSSF",
                "nfStatus": status,
                "nfRegisteredAtSource": (
                    normalized_id in known_registration_ids
                    if known_registration_ids is not None
                    else True
                ),
            }
        )

    output.sort(key=lambda item: item["nfInstanceId"])
    return {"nfInstances": output}


def projected_fields(
    obj: dict,
    *,
    wire_bytes: int,
    known_registration_ids: set[str] | None = None,
) -> dict:
    projected = witness_supported_projection(
        obj, known_registration_ids
    )
    return {
        "status": 200,
        "canonical_bytes": len(encode(projected)),
        "nssf_profiles": len(projected["nfInstances"]),
        "wire_bytes": int(wire_bytes),
        "structure": serialize_counter(structural_counter(projected)),
        "semantic": serialize_projection(semantic_projection(projected)),
    }


def common_path_projection(row: dict) -> dict:
    output = dict(row)
    for suffix in (
        "status",
        "canonical_bytes",
        "nssf_profiles",
        "wire_bytes",
        "structure",
        "semantic",
    ):
        output[f"trusted_{suffix}"] = output[f"consumer_{suffix}"]
    output["reference_scope"] = "same_compromised_nrf_projected_common_mode"
    return output


async def capture(seed: int):
    registration_ids = await await_nf_side_witness()
    await await_scp_port()
    nrf_cid = await enable_native_nrf_instrumentation()

    known_registration_ids = {
        value.lower() for value in registration_ids.values()
    }
    rng = random.Random(seed * 250025 + 41)
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
            # The witness is not a transport response. wire_bytes is an
            # informational field only; the frozen numeric detector consumes
            # canonical_bytes.
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
                "common_witness_supported_projection_from_nf_side_evidence"
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
                    "Stage25 projected warm-up is not exactly paired; "
                    "independent witness projection cannot calibrate all channels"
                )

    nrf_log = await command_output(
        ["docker", "exec", nrf_cid, "cat", "/var/log/open5gs/nrf.log"]
    )
    labels = labels_from_native_nrf_log(seed, nrf_log)
    labels["stage"] = 25

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
            "grep -a -q STAGE24_NATIVE_NRF_LAB_MUTATION " + binary_path,
        ]
    )
    source_sha256 = hashlib.sha256(
        Path("live/stage24-nnrf-handler.c").read_bytes()
    ).hexdigest()

    provenance = {
        "stage": 25,
        "seed": seed,
        "open5gs_source_ref": "v2.7.6",
        "native_nrf_binary_sha256": binary_sha256,
        "instrumented_nrf_source_sha256": source_sha256,
        "native_nrf_binary_contains_stage24_marker": True,
        "consumer_path": "stock_open5gs_scp_to_instrumented_native_nrf",
        "trusted_reference_reads_nrf_discovery": False,
        "trusted_reference_uses_nf_local_registration_logs": True,
        "trusted_reference_uses_direct_nf_liveness": True,
        "witness_registration_ids": registration_ids,
        "witness_projection_fields": [
            "nfInstanceId",
            "nfType",
            "nfStatus",
            "nfRegisteredAtSource",
        ],
        "same_projection_applied_to_trusted_and_consumer": True,
        "numeric_channel_has_external_nrf_independent_reference": True,
        "sparse_channel_has_external_nrf_independent_reference": True,
        "structural_channel_has_external_nrf_independent_reference": True,
        "semantic_channel_has_external_nrf_independent_reference": True,
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
        "STAGE25_CAPTURE_OK "
        f"seed={args.seed} ticks={len(telemetry)} "
        f"episodes={EPISODES} "
        f"warmup_exact={provenance['warmup_exact_pair_fraction']:.3f}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--telemetry-output", default="stage25_telemetry")
    parser.add_argument("--labels-output", default="stage25_private_labels")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
