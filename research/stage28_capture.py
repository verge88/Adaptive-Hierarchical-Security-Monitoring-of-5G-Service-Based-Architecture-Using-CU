"""Stage 28 randomized common-source stress capture.

Stage 27 used a deliberately strong, persistent phantom-profile episode and
observed event recall 1.000. Stage 28 preregisters a *distribution* instead of
fixed attack windows and realizes a private plan independently on every runner.

The native Open5GS NRF receives the private plan through a local file only.
The colluding NF-side witness software mirrors the consumer-visible false state,
so the ordinary pair remains information-free. The signed Stage-27 authority
baseline is introduced only later by a separate verifier job.

Randomized factors:
- episode duration: short / medium / long;
- attack density inside the episode: low / medium / high;
- mutation family: registered phantom, suspended phantom, status substitution;
- phantom multiplicity: one or two;
- clean inter-episode gap: 5..9 samples.

The realized schedule is stored only with private labels.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import re
import secrets
import tempfile

from .stage14_native_scp import NATIVE_SCP, NRF_PATH, h2_exchange
from .stage24_capture import (
    NSSF_WITNESS,
    await_scp_port,
    latest_nf_registration_id,
)
from .stage5_native import native_h2_status

WARMUP_TICKS = 30
EPISODES = 12
KINDS = (
    "phantom_registered",
    "phantom_suspended",
    "status_substitution",
)
DURATION_RANGES = {
    "short": (2, 4),
    "medium": (5, 8),
    "long": (9, 14),
}
DENSITY_RANGES = {
    "low": (0.25, 0.40),
    "medium": (0.45, 0.70),
    "high": (0.75, 1.00),
}
GAP_RANGE = (5, 9)

COMPOSE = [
    "docker", "compose",
    "-f", "live/compose.yaml",
    "-f", "live/stage5-compose.yaml",
    "-f", "live/stage14-scp-compose.yaml",
    "-f", "live/stage28-nrf-compose.yaml",
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


async def await_nf_side_readiness(timeout_s: float = 75.0) -> dict[str, str]:
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
                raise AssertionError("NF-side readiness UUIDs are not unique")
            return output
        except (RuntimeError, ValueError, OSError) as ex:
            last = f"{type(ex).__name__}: {ex}"
            await asyncio.sleep(0.45)
    raise TimeoutError("Stage28 NF-side readiness failed: " + last)


def balanced_labels(values: tuple[str, ...], copies: int) -> list[str]:
    output = list(values) * copies
    secrets.SystemRandom().shuffle(output)
    return output


def build_private_schedule() -> dict:
    rng = secrets.SystemRandom()
    duration_bins = balanced_labels(("short", "medium", "long"), 4)
    density_bins = balanced_labels(("low", "medium", "high"), 4)
    kinds = balanced_labels(KINDS, 4)

    cursor = WARMUP_TICKS
    episodes = []
    entries = []

    for index in range(EPISODES):
        duration_bin = duration_bins[index]
        density_bin = density_bins[index]
        kind = kinds[index]

        duration = rng.randint(*DURATION_RANGES[duration_bin])
        lo, hi = DENSITY_RANGES[density_bin]
        density_target = rng.uniform(lo, hi)
        mutation_count = max(
            1,
            min(duration, int(round(duration * density_target))),
        )
        offsets = sorted(rng.sample(range(duration), mutation_count))
        multiplicity = (
            1 if kind == "status_substitution" else rng.randint(1, 2)
        )

        start = cursor
        end = start + duration
        mutation_ticks = [start + offset for offset in offsets]
        for tick in mutation_ticks:
            entries.append(
                {
                    "tick": tick,
                    "kind": kind,
                    "multiplicity": multiplicity,
                }
            )

        realized_density = mutation_count / duration
        episodes.append(
            {
                "episode": index,
                "kind": kind,
                "duration_bin": duration_bin,
                "density_bin": density_bin,
                "start_tick": start,
                "end_tick": end,
                "duration_ticks": duration,
                "density_target": density_target,
                "realized_density": realized_density,
                "multiplicity": multiplicity,
                "mutation_ticks": mutation_ticks,
            }
        )
        cursor = end + rng.randint(*GAP_RANGE)

    plan_text = "".join(
        f"{entry['tick']}\t{entry['kind']}\t{entry['multiplicity']}\n"
        for entry in entries
    )
    return {
        "episodes": episodes,
        "entries": entries,
        "total_ticks": cursor,
        "plan_text": plan_text,
        "plan_sha256": hashlib.sha256(
            plan_text.encode("utf8")
        ).hexdigest(),
        "plan_nonce": secrets.token_hex(16),
    }


async def install_and_enable_plan(plan_text: str) -> str:
    cid = await container_id("nrf")
    await command_output(
        [
            "docker", "exec", cid, "sh", "-c",
            "mkdir -p /run/stage28 && "
            "rm -f /run/stage28/enabled /run/stage28/plan.tsv",
        ]
    )

    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "plan.tsv"
        local.write_text(plan_text, encoding="utf8")
        await command_output(
            ["docker", "cp", str(local), f"{cid}:/run/stage28/plan.tsv"]
        )

    await command_output(
        [
            "docker", "exec", cid, "sh", "-c",
            "chmod 0400 /run/stage28/plan.tsv && "
            "touch /run/stage28/enabled",
        ]
    )
    return cid


async def consumer_counts() -> tuple[int, int]:
    response = await h2_exchange(
        NATIVE_SCP,
        NRF_PATH,
        target="http://nrf:80",
        timeout=5,
    )
    if response.status != 200:
        raise AssertionError(
            f"Stage28 NRF discovery returned HTTP {response.status}"
        )
    obj = json.loads(response.body)
    instances = obj.get("nfInstances")
    if not isinstance(instances, list):
        raise AssertionError("Stage28 NRF discovery lacks nfInstances")

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
            "Stage28 native NRF log does not match private plan: "
            f"observed={observed} expected={schedule['entries']}"
        )

    return {
        "stage": 28,
        "seed": seed,
        "warmup_ticks": WARMUP_TICKS,
        "total_ticks": schedule["total_ticks"],
        "episodes": schedule["episodes"],
        "private_plan_entries": schedule["entries"],
        "private_plan_sha256": schedule["plan_sha256"],
        "private_plan_nonce": schedule["plan_nonce"],
        "native_nrf_inprocess_log_marker_count": len(observed),
        "common_source_attack": True,
        "distribution_preregistered_not_realized_schedule": True,
        "fault_location": (
            "inside open5gs-nrfd src/nrf/nnrf-handler.c "
            "nrf_nnrf_handle_nf_discover before stock server send"
        ),
    }


async def capture(seed: int):
    readiness_ids = await await_nf_side_readiness()
    if len(readiness_ids) != 2:
        raise AssertionError("Stage28 requires exactly two live NSSF sources")
    await await_scp_port()

    schedule = build_private_schedule()
    nrf_cid = await install_and_enable_plan(schedule["plan_text"])

    raw_rows = []
    for tick in range(schedule["total_ticks"]):
        witness_first = bool(secrets.randbelow(2))
        consumer_count, consumer_registered = await consumer_counts()

        # Deliberate common-source compromise: ordinary witness software
        # mirrors the same false state as the compromised NRF output.
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
        raise AssertionError("Stage28 common-source mirroring failed")

    clean = raw_rows[:WARMUP_TICKS]
    if not all(
        row["consumer_nssf_count"] == 2
        and row["consumer_registered_count"] == 2
        for row in clean
    ):
        raise AssertionError("Stage28 clean warm-up is not 2/2")

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

    provenance = {
        "stage": 28,
        "seed": seed,
        "open5gs_source_ref": "v2.7.6",
        "native_nrf_binary_sha256": binary_sha256,
        "instrumented_nrf_source_sha256": source_sha256,
        "native_nrf_binary_contains_stage28_marker": True,
        "consumer_path": "stock_open5gs_scp_to_instrumented_native_nrf",
        "preattack_nf_side_readiness_ids": readiness_ids,
        "preattack_readiness_used_as_detector_reference": False,
        "signed_attestation_available_to_capture_job": False,
        "realized_private_plan_available_to_blind_detector": False,
        "all_common_source_rows_equal": True,
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
        "STAGE28_CAPTURE_OK "
        f"seed={args.seed} ticks={len(raw_rows)} "
        f"episodes={EPISODES} "
        f"mutations={labels['native_nrf_inprocess_log_marker_count']}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--telemetry-output", default="stage28_raw")
    parser.add_argument("--labels-output", default="stage28_private_labels")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
