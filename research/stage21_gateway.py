"""Stage 21 randomized blind post-SCP semantic fault gateway.

This is a new private live generator. It does not reuse the Stage-18 fixed
sparse tick set. Every consumer request still traverses the genuine native
Open5GS SCP -> NRF path first; only the consumer-facing response copy can be
mutated afterwards.

Ground-truth scheduling and mutation details remain private to capture/audit.
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
    "identity_value_sparse",
    "status_value_sparse",
    "number_value_sparse",
    "scheme_value_sparse",
    "structural_leaf_delete_sparse",
    "profile_drop_persistent",
    "boundary_cross_profile_identity_swap",
)
REPETITIONS = {
    "identity_value_sparse": 2,
    "status_value_sparse": 2,
    "number_value_sparse": 2,
    "scheme_value_sparse": 2,
    "structural_leaf_delete_sparse": 2,
    "profile_drop_persistent": 2,
    "boundary_cross_profile_identity_swap": 2,
}
EPISODES = sum(REPETITIONS.values())
TOTAL_TICKS = WARMUP_TICKS + EPISODES * (
    EPISODE_TICKS + GAP_TICKS
)
PRIMARY_KINDS = tuple(
    kind for kind in ATTACK_KINDS
    if not kind.startswith("boundary_")
)


def build_private_schedule(seed: int) -> list[dict]:
    rng = random.Random(seed * 210021 + 131)
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
        if kind in (
            "profile_drop_persistent",
            "boundary_cross_profile_identity_swap",
        ):
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
                "boundary": kind.startswith("boundary_"),
            }
        )
        cursor = end + GAP_TICKS
    if cursor != TOTAL_TICKS:
        raise AssertionError("Stage21 schedule length mismatch")
    return episodes


def _episode_for_tick(schedule: list[dict], tick: int):
    for episode in schedule:
        if episode["start_tick"] <= tick < episode["end_tick"]:
            return episode
    return None


def _profiles(payload: dict) -> list[dict]:
    rows = payload.get("nfInstances")
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _mutate_identity(payload: dict) -> tuple[bool, str]:
    profiles = _profiles(payload)
    if not profiles or not isinstance(
        profiles[0].get("nfInstanceId"), str
    ):
        return False, ""
    original = profiles[0]["nfInstanceId"]
    replacement = "f" * len(original)
    if replacement == original:
        replacement = "e" * len(original)
    profiles[0]["nfInstanceId"] = replacement
    return True, "$/nfInstances[]/nfInstanceId"


def _mutate_status(payload: dict) -> tuple[bool, str]:
    profiles = _profiles(payload)
    if not profiles or not isinstance(
        profiles[0].get("nfStatus"), str
    ):
        return False, ""
    current = profiles[0]["nfStatus"]
    profiles[0]["nfStatus"] = (
        "SUSPENDED" if current != "SUSPENDED" else "REGISTERED"
    )
    return True, "$/nfInstances[]/nfStatus"


def _mutate_number(payload: dict) -> tuple[bool, str]:
    profiles = _profiles(payload)
    for profile in profiles:
        for key in ("heartBeatTimer", "priority", "capacity", "load"):
            value = profile.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if isinstance(value, int):
                    profile[key] = value + 1
                else:
                    profile[key] = value + 1.0
                return True, f"$/nfInstances[]/{key}"
    return False, ""


def _mutate_scheme(payload: dict) -> tuple[bool, str]:
    profiles = _profiles(payload)
    for profile in profiles:
        services = profile.get("nfServices")
        if not isinstance(services, list):
            services = profile.get("services")
        if not isinstance(services, list):
            continue
        for service in services:
            if not isinstance(service, dict):
                continue
            value = service.get("scheme")
            if isinstance(value, str):
                service["scheme"] = (
                    "grpc" if value != "grpc" else "http"
                )
                return True, "$/nfInstances[]/nfServices[]/scheme"
    return False, ""


def _delete_structural_leaf(payload: dict) -> tuple[bool, str]:
    protected = {"nfInstanceId", "nfType", "nfStatus"}
    for profile in _profiles(payload):
        candidates = [
            key
            for key, value in profile.items()
            if key not in protected
            and not isinstance(value, (dict, list))
        ]
        if candidates:
            key = sorted(candidates)[0]
            del profile[key]
            return True, f"$/nfInstances[]/{key}"
    if "validityPeriod" in payload:
        del payload["validityPeriod"]
        return True, "$/validityPeriod"
    return False, ""


def _drop_profile(payload: dict) -> tuple[bool, str]:
    rows = payload.get("nfInstances")
    if isinstance(rows, list) and len(rows) >= 2:
        rows.pop()
        return True, "$/nfInstances[]"
    return False, ""


def _swap_profile_identities(payload: dict) -> tuple[bool, str]:
    profiles = _profiles(payload)
    if len(profiles) < 2:
        return False, ""
    left = profiles[0].get("nfInstanceId")
    right = profiles[1].get("nfInstanceId")
    if not isinstance(left, str) or not isinstance(right, str):
        return False, ""
    profiles[0]["nfInstanceId"] = right
    profiles[1]["nfInstanceId"] = left
    return True, "$/nfInstances[]/nfInstanceId"


def mutate_payload(payload: dict, kind: str) -> tuple[dict, bool, str]:
    output = copy.deepcopy(payload)
    functions = {
        "identity_value_sparse": _mutate_identity,
        "status_value_sparse": _mutate_status,
        "number_value_sparse": _mutate_number,
        "scheme_value_sparse": _mutate_scheme,
        "structural_leaf_delete_sparse": _delete_structural_leaf,
        "profile_drop_persistent": _drop_profile,
        "boundary_cross_profile_identity_swap": _swap_profile_identities,
    }
    mutated, field = functions[kind](output)
    return output, mutated, field


class Stage21PostSCPGateway:
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
            headers.get(":path") != "/stage21/nrf"
            or headers.get(":method") != "GET"
        ):
            return 404, {"error": "not stage21 endpoint"}
        if self.tick >= TOTAL_TICKS:
            return 429, {"error": "stage21 tick budget exhausted"}

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
            "stage": 21,
            "seed": self.seed,
            "warmup_ticks": WARMUP_TICKS,
            "total_ticks": TOTAL_TICKS,
            "episodes": episodes,
            "primary_kinds": list(PRIMARY_KINDS),
            "fault_location": (
                "research consumer-facing gateway AFTER genuine native "
                "Open5GS SCP response"
            ),
            "native_open5gs_scp_binary_modified": False,
            "native_open5gs_nrf_binary_modified": False,
            "schedule_randomized_per_seed": True,
            "sparse_pulse_positions_randomized_per_episode": True,
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
            "stage18_fixed_sparse_schedule_reused": False,
        }
