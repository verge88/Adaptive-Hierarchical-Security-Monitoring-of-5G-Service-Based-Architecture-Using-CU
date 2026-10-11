"""Stage 18 blind post-SCP fault gateway.

The gateway is a research-only fault injector placed AFTER a genuine native
Open5GS SCP route. It never modifies the native Open5GS SCP/NRF containers.
Every consumer request is first forwarded through the genuine native SCP to
the genuine NRF. Only the returned consumer-facing JSON copy may be altered.

Attack scheduling and ground-truth labels live in this module/process. The
Stage-18 detector runs in a separate GitHub Actions job that receives only
telemetry and therefore cannot read these labels.
"""
from __future__ import annotations

import copy
import json
import random

from .h2_wire import H2Server
from .stage14_native_scp import (
    NATIVE_SCP,
    NRF_PATH,
    discovered_nssf_ids,
    h2_exchange,
)

WARMUP_TICKS = 30
EPISODE_TICKS = 12
GAP_TICKS = 6
ATTACK_KINDS = (
    "profile_duplicate",
    "profile_drop",
    "padding_sparse",
    "metadata_strip_sparse",
)
REPETITIONS_PER_KIND = 3
EPISODES = len(ATTACK_KINDS) * REPETITIONS_PER_KIND
TOTAL_TICKS = WARMUP_TICKS + EPISODES * (
    EPISODE_TICKS + GAP_TICKS
)
SPARSE_LOCAL_TICKS = frozenset((1, 4, 8, 10))


def build_private_schedule(seed: int) -> list[dict]:
    """Generate balanced private episodes, all strictly after warm-up."""
    rng = random.Random(seed * 18018 + 71)
    kinds = [
        kind
        for kind in ATTACK_KINDS
        for _ in range(REPETITIONS_PER_KIND)
    ]
    rng.shuffle(kinds)

    episodes = []
    cursor = WARMUP_TICKS
    for episode_id, kind in enumerate(kinds):
        start = cursor
        end = start + EPISODE_TICKS
        direction = (
            "positive"
            if kind in ("profile_duplicate", "padding_sparse")
            else "negative"
        )
        episodes.append(
            {
                "episode": episode_id,
                "kind": kind,
                "direction": direction,
                "start_tick": start,
                "end_tick": end,
            }
        )
        cursor = end + GAP_TICKS
    if cursor != TOTAL_TICKS:
        raise AssertionError("Stage18 schedule length mismatch")
    return episodes


def _episode_for_tick(schedule: list[dict], tick: int):
    for episode in schedule:
        if episode["start_tick"] <= tick < episode["end_tick"]:
            return episode
    return None


def _strip_optional_metadata(payload: dict) -> bool:
    if "validityPeriod" in payload:
        del payload["validityPeriod"]
        return True

    instances = payload.get("nfInstances")
    if not isinstance(instances, list) or not instances:
        return False

    protected = {
        "nfInstanceId",
        "nfType",
        "nfStatus",
    }
    for profile in instances:
        if not isinstance(profile, dict):
            continue
        optional = sorted(
            key for key in profile if key not in protected
        )
        if optional:
            del profile[optional[0]]
            return True
    return False


def mutate_payload(
    payload: dict,
    kind: str,
    local_tick: int,
) -> tuple[dict, bool]:
    """Return the consumer-visible copy and whether a fault was applied."""
    output = copy.deepcopy(payload)
    instances = output.get("nfInstances")

    if kind == "profile_duplicate":
        if isinstance(instances, list) and instances:
            instances.append(copy.deepcopy(instances[0]))
            return output, True
        return output, False

    if kind == "profile_drop":
        if isinstance(instances, list) and len(instances) >= 2:
            instances.pop()
            return output, True
        return output, False

    if kind == "padding_sparse":
        if local_tick in SPARSE_LOCAL_TICKS:
            output["_stage18_padding"] = "x" * 32
            return output, True
        return output, False

    if kind == "metadata_strip_sparse":
        if local_tick in SPARSE_LOCAL_TICKS:
            return output, _strip_optional_metadata(output)
        return output, False

    raise ValueError(kind)


class BlindPostSCPGateway:
    """Consumer gateway with a private fault schedule.

    The handler exposes no tick, attack kind, direction or ground-truth field.
    It only returns the consumer-visible NRF response copy.
    """

    def __init__(self, seed: int):
        self.seed = seed
        self.schedule = build_private_schedule(seed)
        self.tick = 0
        self.server = H2Server(self.handle)
        self.applied_fault_ticks: list[int] = []
        self.upstream_statuses: list[int] = []
        self.upstream_nssf_counts: list[int] = []

    async def start(self):
        await self.server.start()
        return self

    async def close(self):
        await self.server.close()

    async def handle(self, headers, body):
        if (
            headers.get(":path") != "/stage18/nrf"
            or headers.get(":method") != "GET"
        ):
            return 404, {"error": "not stage18 endpoint"}

        if self.tick >= TOTAL_TICKS:
            return 429, {"error": "stage18 tick budget exhausted"}

        upstream = await h2_exchange(
            NATIVE_SCP,
            NRF_PATH,
            target="http://nrf:80",
            timeout=4,
        )
        ids = discovered_nssf_ids(upstream)
        payload = json.loads(upstream.body)

        tick = self.tick
        self.tick += 1
        self.upstream_statuses.append(upstream.status)
        self.upstream_nssf_counts.append(len(ids))

        episode = _episode_for_tick(self.schedule, tick)
        mutated = False
        if episode is not None:
            local_tick = tick - episode["start_tick"]
            payload, mutated = mutate_payload(
                payload,
                episode["kind"],
                local_tick,
            )
            if mutated:
                self.applied_fault_ticks.append(tick)

        return upstream.status, payload

    def private_labels(self) -> dict:
        mutation_set = set(self.applied_fault_ticks)
        episodes = []
        for episode in self.schedule:
            item = dict(episode)
            item["mutation_ticks"] = [
                tick
                for tick in range(
                    episode["start_tick"],
                    episode["end_tick"],
                )
                if tick in mutation_set
            ]
            episodes.append(item)

        return {
            "stage": 18,
            "seed": self.seed,
            "warmup_ticks": WARMUP_TICKS,
            "total_ticks": TOTAL_TICKS,
            "episodes": episodes,
            "fault_location": (
                "research consumer-facing gateway AFTER genuine native "
                "Open5GS SCP response"
            ),
            "native_open5gs_scp_binary_modified": False,
            "native_open5gs_nrf_binary_modified": False,
        }

    def public_provenance(self) -> dict:
        return {
            "seed": self.seed,
            "native_scp_upstream_calls": self.tick,
            "all_native_scp_upstream_http_200": (
                bool(self.upstream_statuses)
                and all(status == 200 for status in self.upstream_statuses)
            ),
            "min_native_nssf_profiles_seen_upstream": (
                min(self.upstream_nssf_counts)
                if self.upstream_nssf_counts
                else 0
            ),
            "fault_labels_excluded": True,
            "consumer_gateway_is_research_code": True,
            "native_open5gs_scp_binary_modified": False,
        }
