"""Stage 22 controlled SCP-compromise effect model.

This module does NOT exploit or patch the Open5GS SCP binary.  It models the
observable effect of a compromised SCP at its consumer-facing output boundary:
the genuine native Open5GS SCP forwards a request to the genuine NRF first,
then a research-only facade is allowed to alter the response before returning
it to the consumer.

The important Stage-22 trust-boundary change is elsewhere: the trusted
reference bypasses the SCP and queries the native NRF directly.  Therefore a
fault attributed to the SCP is no longer common-mode across both observations.
"""
from __future__ import annotations

import json
import random

from .h2_wire import H2Server
from .stage14_native_scp import (
    NATIVE_SCP,
    NRF_PATH,
    discovered_nssf_ids,
    h2_exchange,
)
from .stage21_gateway import mutate_payload

WARMUP_TICKS = 30
EPISODE_TICKS = 12
GAP_TICKS = 6

ATTACK_KINDS = (
    "identity_value_sparse",
    "status_value_sparse",
    "scheme_value_sparse",
    "structural_leaf_delete_sparse",
    "profile_drop_persistent",
)
REPETITIONS = {kind: 2 for kind in ATTACK_KINDS}
EPISODES = sum(REPETITIONS.values())
TOTAL_TICKS = WARMUP_TICKS + EPISODES * (EPISODE_TICKS + GAP_TICKS)


def build_private_schedule(seed: int) -> list[dict]:
    """Create a fresh randomized Stage-22 evaluation schedule."""
    rng = random.Random(seed * 220022 + 197)
    kinds = [
        kind
        for kind in ATTACK_KINDS
        for _ in range(REPETITIONS[kind])
    ]
    rng.shuffle(kinds)

    episodes = []
    cursor = WARMUP_TICKS
    for episode_id, kind in enumerate(kinds):
        start = cursor
        end = start + EPISODE_TICKS
        if kind == "profile_drop_persistent":
            local_pulses = tuple(range(EPISODE_TICKS))
        else:
            count = rng.choice((3, 4, 5))
            local_pulses = tuple(
                sorted(rng.sample(range(EPISODE_TICKS), count))
            )
        episodes.append(
            {
                "episode": episode_id,
                "kind": kind,
                "start_tick": start,
                "end_tick": end,
                "pulse_local_ticks": list(local_pulses),
            }
        )
        cursor = end + GAP_TICKS

    if cursor != TOTAL_TICKS:
        raise AssertionError("Stage22 schedule length mismatch")
    return episodes


def episode_for_tick(schedule: list[dict], tick: int):
    for episode in schedule:
        if episode["start_tick"] <= tick < episode["end_tick"]:
            return episode
    return None


class Stage22CompromisedSCPFacade:
    """Research facade representing arbitrary corruption at SCP output.

    The native SCP and NRF binaries remain untouched.  The facade exists only
    on the disposable lab path so that the downstream observable consequence of
    SCP compromise can be evaluated without introducing an exploit mechanism.
    """

    def __init__(self, seed: int):
        self.seed = seed
        self.schedule = build_private_schedule(seed)
        self.tick = 0
        self.server = H2Server(self.handle)
        self.mutations: dict[int, str] = {}
        self.upstream_statuses: list[int] = []
        self.upstream_nssf_counts: list[int] = []

    async def start(self):
        await self.server.start()
        return self

    async def close(self):
        await self.server.close()

    async def handle(self, headers, body):
        if (
            headers.get(":path") != "/stage22/scp-nrf"
            or headers.get(":method") != "GET"
        ):
            return 404, {"error": "not stage22 endpoint"}
        if self.tick >= TOTAL_TICKS:
            return 429, {"error": "stage22 tick budget exhausted"}

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

        episode = episode_for_tick(self.schedule, tick)
        if episode is not None:
            local_tick = tick - episode["start_tick"]
            if local_tick in set(episode["pulse_local_ticks"]):
                payload, mutated, field = mutate_payload(
                    payload, episode["kind"]
                )
                if mutated:
                    self.mutations[tick] = field

        return upstream.status, payload

    def private_labels(self) -> dict:
        episodes = []
        for episode in self.schedule:
            item = dict(episode)
            item["mutation_ticks"] = [
                tick
                for tick in range(
                    item["start_tick"], item["end_tick"]
                )
                if tick in self.mutations
            ]
            item["mutated_fields"] = {
                str(tick): self.mutations[tick]
                for tick in item["mutation_ticks"]
            }
            episodes.append(item)

        return {
            "stage": 22,
            "seed": self.seed,
            "warmup_ticks": WARMUP_TICKS,
            "total_ticks": TOTAL_TICKS,
            "episodes": episodes,
            "primary_kinds": list(ATTACK_KINDS),
            "fault_model": (
                "arbitrary response corruption at the SCP consumer-facing "
                "output boundary after genuine native SCP->NRF forwarding"
            ),
            "native_open5gs_scp_binary_modified": False,
            "native_open5gs_nrf_binary_modified": False,
            "native_binary_exploitation_performed": False,
            "schedule_randomized_per_seed": True,
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
            "fault_injection_at_scp_output_boundary": True,
            "native_open5gs_scp_binary_modified": False,
            "native_open5gs_nrf_binary_modified": False,
            "native_binary_exploitation_performed": False,
            "claim_scope": (
                "effect-level SCP compromise validation with an independent "
                "reference outside the SCP trust domain"
            ),
        }
