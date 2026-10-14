"""Stage 27 capture: coordinated NRF + NF-witness false state.

The native Open5GS NRF is the Stage-26 in-process persistent phantom build.
Separately, the NF-side witness layer is modeled as compromised by adding the
same phantom logical NSSF to its independently collected NF-side state.

The capture job never receives the Stage-27 attestation private key or signed
manifest. It emits label-free consumer and compromised-witness projections.
The attestation domain is joined only in the blind detector job.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import random

from .stage14_native_scp import NATIVE_SCP, NRF_PATH, h2_exchange
from .stage24_capture import (
    await_nf_side_witness,
    await_scp_port,
    command_output,
    witness_object,
)
from .stage26_capture import (
    ATTACK_KIND as NRF_ATTACK_KIND,
    COMPOSE,
    EPISODES,
    PHANTOM_ID,
    TOTAL_TICKS,
    WARMUP_TICKS,
    compose_output,
    container_id,
    enable_native_nrf_instrumentation,
    labels_from_native_nrf_log,
)

WITNESS_ATTACK_KIND = "coordinated_phantom_profile_witness"


def ordinal_projection(obj: dict) -> dict:
    """Map runtime NSSF identities to a stable slot representation.

    Runtime UUIDs are deliberately discarded so a signed deployment contract can
    be compared without trusting NRF- or NF-reported UUID values. Ordering is
    deterministic by normalized UUID before assigning logical slots.
    """
    instances = obj.get("nfInstances")
    if not isinstance(instances, list):
        raise AssertionError("Stage27 object lacks nfInstances")

    normalized = []
    for item in instances:
        if not isinstance(item, dict) or item.get("nfType") != "NSSF":
            continue
        nf_id = item.get("nfInstanceId")
        status = item.get("nfStatus")
        if not isinstance(nf_id, str) or not isinstance(status, str):
            raise AssertionError("Stage27 NSSF profile lacks identity/status")
        normalized.append((nf_id.lower(), status))

    normalized.sort()
    return {
        "nfInstances": [
            {
                "slot": f"nssf-{index + 1}",
                "nfType": "NSSF",
                "nfStatus": status,
            }
            for index, (_nf_id, status) in enumerate(normalized)
        ]
    }


def compromised_witness_object(true_witness: dict, tick: int) -> dict:
    """Model coordinated compromise of the NF-side witness layer.

    The true witness is collected independently from NSSF-local state, then the
    compromised witness layer injects the same phantom claim during the frozen
    Stage-26 attack episodes. This does not copy the NRF response.
    """
    obj = json.loads(json.dumps(true_witness))
    if tick >= WARMUP_TICKS:
        local = (tick - WARMUP_TICKS) % 16
        if local < 12:
            obj["nfInstances"].append(
                {
                    "nfInstanceId": PHANTOM_ID,
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                }
            )
    return obj


def consumer_projection_from_response(response) -> dict:
    if response.status != 200:
        raise AssertionError(
            f"Compromised NRF discovery returned HTTP {response.status}"
        )
    return ordinal_projection(json.loads(response.body))


async def capture(seed: int):
    registration_ids = await await_nf_side_witness()
    await await_scp_port()
    nrf_cid = await enable_native_nrf_instrumentation()

    rng = random.Random(seed * 270027 + 47)
    telemetry = []
    exact_pair_count = 0

    for tick in range(TOTAL_TICKS):
        witness_first = rng.randrange(2) == 0

        async def compromised_nf_witness():
            true_obj = await witness_object(registration_ids)
            false_obj = compromised_witness_object(true_obj, tick)
            return ordinal_projection(false_obj)

        async def compromised_nrf_view():
            response = await h2_exchange(
                NATIVE_SCP,
                NRF_PATH,
                target="http://nrf:80",
                timeout=5,
            )
            return consumer_projection_from_response(response)

        if witness_first:
            witness_projection = await compromised_nf_witness()
            consumer_projection = await compromised_nrf_view()
        else:
            consumer_projection = await compromised_nrf_view()
            witness_projection = await compromised_nf_witness()

        if witness_projection != consumer_projection:
            raise AssertionError(
                "Stage27 coordinated false-state invariant failed "
                f"at tick {tick}: witness={witness_projection} "
                f"consumer={consumer_projection}"
            )
        exact_pair_count += 1

        telemetry.append(
            {
                "seed": seed,
                "tick": tick,
                "witness_first": witness_first,
                "consumer_projection": consumer_projection,
                "compromised_witness_projection": witness_projection,
                "pairwise_false_state_exact": True,
            }
        )

    nrf_log = await command_output(
        ["docker", "exec", nrf_cid, "cat", "/var/log/open5gs/nrf.log"]
    )
    labels = labels_from_native_nrf_log(seed, nrf_log)
    labels["stage"] = 27
    labels["nrf_attack_kind"] = NRF_ATTACK_KIND
    labels["witness_attack_kind"] = WITNESS_ATTACK_KIND
    labels["coordinated_false_state"] = True

    binary_path = "/src/open5gs/build/src/nrf/open5gs-nrfd"
    binary_line = (
        await command_output(
            ["docker", "exec", nrf_cid, "sha256sum", binary_path]
        )
    ).strip()
    binary_sha256 = binary_line.split()[0]
    source_sha256 = hashlib.sha256(
        Path("live/stage26-nnrf-handler.c").read_bytes()
    ).hexdigest()

    provenance = {
        "stage": 27,
        "seed": seed,
        "open5gs_source_ref": "v2.7.6",
        "native_nrf_binary_sha256": binary_sha256,
        "instrumented_nrf_source_sha256": source_sha256,
        "consumer_path": "stock_scp_to_stage26_instrumented_native_nrf",
        "nrf_false_state_generated_in_native_process": True,
        "nf_witness_false_state_generated_separately": True,
        "nf_witness_false_state_copies_consumer_response": False,
        "coordinated_pair_exact_fraction": exact_pair_count / TOTAL_TICKS,
        "attestation_manifest_received_by_capture_job": False,
        "attestation_private_key_received_by_capture_job": False,
        "runtime_registration_ids_used_only_inside_compromised_witness": True,
        "label_free_telemetry_contains_attack_labels": False,
        "native_nrf_inprocess_marker_count": (
            labels["native_nrf_inprocess_log_marker_count"]
        ),
    }
    return telemetry, labels, provenance, nrf_log


async def main_async(args):
    telemetry, labels, provenance, nrf_log = await capture(args.seed)

    telemetry_root = Path(args.telemetry_output)
    labels_root = Path(args.labels_output)
    telemetry_root.mkdir(parents=True, exist_ok=True)
    labels_root.mkdir(parents=True, exist_ok=True)

    (telemetry_root / "telemetry.json").write_text(
        json.dumps(telemetry, indent=2), encoding="utf8"
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
        f"seed={args.seed} ticks={len(telemetry)} "
        f"episodes={EPISODES} "
        f"pair_exact={provenance['coordinated_pair_exact_fraction']:.3f}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--telemetry-output", default="stage27_telemetry")
    parser.add_argument("--labels-output", default="stage27_private_labels")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
