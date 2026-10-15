"""Stage 37 randomized-topology external Open5GS collector.

Stage 37 removes the fixed-scenario limitation of Stage 36.  Each run varies
lifecycle topology/order, transition duration, attack density, attacked NSSF
slot, mutation family and mutation value.  Private attack labels never enter
the verifier request.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import secrets
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

STAGE = 37
OPEN5GS_REF = "v2.7.6"
POLICY_SHA256 = os.environ["STAGE37_POLICY_SHA256"].lower()
SERVICE_REVISION = os.environ.get("STAGE37_COLLECTOR_REVISION", "unrecorded")
VERIFIER_A = os.environ["STAGE37_VERIFIER_A_ENDPOINT"].rstrip("/")
VERIFIER_B = os.environ["STAGE37_VERIFIER_B_ENDPOINT"].rstrip("/")
VERIFIER_TOKEN = os.environ["STAGE37_COLLECTOR_TO_VERIFIER_TOKEN"]
SOAK_TICKS = 120
MAX_BODY = 128_000
PLAN_ROOT = Path("/run/stage37")

_private_pem = os.environ.get("STAGE37_COLLECTOR_PRIVATE_KEY_PEM")
if not _private_pem:
    raise RuntimeError("STAGE37_COLLECTOR_PRIVATE_KEY_PEM is required")
PRIVATE_KEY = serialization.load_pem_private_key(_private_pem.encode("utf8"), password=None)
if not isinstance(PRIVATE_KEY, ec.EllipticCurvePrivateKey):
    raise RuntimeError("collector key must be EC")
PUBLIC_KEY_PEM = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY_PEM).hexdigest()

# Reuse only stock Open5GS lifecycle/discovery/projection helpers from Stage 34.
os.environ.setdefault("STAGE34_POLICY_SHA256", POLICY_SHA256)
os.environ.setdefault("STAGE34_COLLECTOR_REVISION", SERVICE_REVISION)
os.environ.setdefault("STAGE34_COLLECTOR_PRIVATE_KEY_PEM", _private_pem)
_spec = importlib.util.spec_from_file_location(
    "stage34_collector_helpers", "/opt/stage37/stage34_collector_service.py"
)
s34 = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(s34)
s34.PLAN_ROOT = PLAN_ROOT
s34.CONFIG_ROOT = Path("/opt/stage37")

RUN_LOCK = threading.Lock()
SEQUENCE_LOCK = threading.Lock()
COLLECTOR_SEQUENCE = 0

SLOTS = ("nssf1", "nssf2")
SLOT_CODE = {"nssf1": 1, "nssf2": 2}
KINDS = (
    "identity_replacement",
    "endpoint_substitution",
    "service_injection",
    "fqdn_substitution",
)
DENSITY_RANGES = {
    "low": (0.20, 0.35),
    "medium": (0.40, 0.55),
    "high": (0.60, 0.80),
}


def canonical_bytes(doc) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def next_sequence() -> int:
    global COLLECTOR_SEQUENCE
    with SEQUENCE_LOCK:
        COLLECTOR_SEQUENCE += 1
        return COLLECTOR_SEQUENCE


def other_slot(slot: str) -> str:
    return "nssf2" if slot == "nssf1" else "nssf1"


def topology_template(seed: int) -> list[tuple[str, str]]:
    # Balanced over four topologies/orders for any block of four seeds.
    templates = (
        (("stop", "nssf1"), ("start", "nssf1"), ("restart", "nssf2")),
        (("stop", "nssf2"), ("start", "nssf2"), ("restart", "nssf1")),
        (("restart", "nssf1"), ("stop", "nssf2"), ("start", "nssf2")),
        (("restart", "nssf2"), ("stop", "nssf1"), ("start", "nssf1")),
    )
    return list(templates[seed % len(templates)])


def build_scenario(seed: int, challenge_nonce: str) -> tuple[dict, str]:
    schedule_secret = secrets.token_hex(32)
    digest = hashlib.sha256(
        f"{seed}:{challenge_nonce}:{schedule_secret}".encode("utf8")
    ).digest()
    rng = random.Random(int.from_bytes(digest, "big"))

    pre_ticks = rng.randint(3, 6)
    post_ticks = rng.randint(3, 6)
    density_bins = ["low", "medium", "high"]
    rng.shuffle(density_bins)

    cursor = pre_ticks
    events = []
    attack_slots = []
    for index, (operation, slot) in enumerate(topology_template(seed)):
        phase = f"transition_{index}"
        duration = rng.randint(8, 14)
        density_bin = density_bins[index]
        lo, hi = DENSITY_RANGES[density_bin]
        target_density = rng.uniform(lo, hi)
        attack_count = max(2, min(duration, round(duration * target_density)))
        offsets = sorted(rng.sample(range(duration), attack_count))
        attack_ticks = [cursor + offset for offset in offsets]
        stable_slot = other_slot(slot)

        events.append(
            {
                "index": index,
                "operation": operation,
                "slot": slot,
                "stable_slot": stable_slot,
                "phase": phase,
                "pre_reference": "initial" if index == 0 else f"ref_{index-1}",
                "post_reference": f"ref_{index}",
                "start_tick": cursor,
                "end_tick": cursor + duration - 1,
                "duration_ticks": duration,
                "density_bin": density_bin,
                "realized_density": attack_count / duration,
                "attack_ticks": attack_ticks,
            }
        )
        for tick in attack_ticks:
            attack_slots.append((tick, index, stable_slot))
        cursor += duration

    # Balance mutation families within each run, then randomize assignment.
    family_pool = [KINDS[i % len(KINDS)] for i in range(len(attack_slots))]
    rng.shuffle(family_pool)

    entries = []
    for (tick, event_index, target_slot), kind in zip(
        sorted(attack_slots), family_pool
    ):
        variant = rng.randint(1, 4)
        parameter = SLOT_CODE[target_slot] * 100 + variant
        entries.append(
            {
                "tick": tick,
                "event_index": event_index,
                "kind": kind,
                "target_slot": target_slot,
                "variant": variant,
                "parameter": parameter,
            }
        )

    total_transition_ticks = cursor
    steady_post_start = cursor
    soak_start = steady_post_start + post_ticks
    total_ticks = soak_start + SOAK_TICKS

    plan_text = "".join(
        f"{row['tick']}\t{row['kind']}\t{row['parameter']}\n"
        for row in entries
    )
    public_lifecycle = {
        "template_id": seed % 4,
        "pre_ticks": pre_ticks,
        "post_ticks": post_ticks,
        "steady_post_start": steady_post_start,
        "soak_start": soak_start,
        "events": [
            {
                key: event[key]
                for key in (
                    "index", "operation", "slot", "stable_slot", "phase",
                    "pre_reference", "post_reference", "start_tick",
                    "end_tick", "duration_ticks",
                )
            }
            for event in events
        ],
    }
    private = {
        "events": events,
        "entries": entries,
        "plan_text": plan_text,
        "plan_sha256": hashlib.sha256(plan_text.encode("utf8")).hexdigest(),
        "schedule_secret_sha256": hashlib.sha256(
            schedule_secret.encode("ascii")
        ).hexdigest(),
        "total_ticks": total_ticks,
        "public_lifecycle": public_lifecycle,
    }
    return private, schedule_secret


def install_plan(scenario: dict) -> None:
    PLAN_ROOT.mkdir(parents=True, exist_ok=True)
    (PLAN_ROOT / "plan.tsv").write_text(scenario["plan_text"], encoding="utf8")
    os.chmod(PLAN_ROOT / "plan.tsv", 0o400)
    (PLAN_ROOT / "enabled").touch()


def enable_hook() -> None:
    (PLAN_ROOT / "enabled").touch()


def disable_hook() -> None:
    (PLAN_ROOT / "enabled").unlink(missing_ok=True)


async def stop_nf(name: str) -> None:
    proc = s34.PROCESSES.get(name)
    if proc is None:
        raise RuntimeError(f"missing process {name}")
    if proc.poll() is None:
        proc.terminate()
    deadline = time.time() + 4
    while proc.poll() is None and time.time() < deadline:
        await asyncio.sleep(0.05)
    if proc.poll() is None:
        proc.kill()
        await asyncio.sleep(0.05)


async def start_nf(name: str) -> None:
    config = "nssf1.yaml" if name == "nssf1" else "nssf2.yaml"
    s34.start_process(name, "/src/open5gs/build/src/nssf/open5gs-nssfd", config)
    await asyncio.sleep(0.05)


async def wait_count(expected: int, timeout: float = 8.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            obj, _ = await s34.discover()
            projection = s34.relational_projection(obj)
            count, registered = s34.count_projection(projection)
            last = (count, registered, projection)
            if count == expected and registered == expected:
                return projection
        except Exception:
            pass
        await asyncio.sleep(0.05)
    raise RuntimeError(f"failed to settle at {expected} NSSF profiles: {last}")


async def clean_reference(expected_count: int) -> dict:
    disable_hook()
    projection = await wait_count(expected_count)
    for _ in range(3):
        obj, _ = await s34.discover()
        check = s34.relational_projection(obj)
        if canonical_bytes(check) != canonical_bytes(projection):
            raise RuntimeError("reference state not stable")
        await asyncio.sleep(0.02)
    return projection


async def collect_tick(tick: int, phase: str) -> dict:
    started = time.perf_counter()
    obj, raw = await s34.discover()
    latency_ms = (time.perf_counter() - started) * 1000
    projection = s34.relational_projection(obj)
    count, registered = s34.count_projection(projection)
    return {
        "tick": tick,
        "phase": phase,
        "projection": projection,
        "legacy_nssf_count": count,
        "legacy_registered_count": registered,
        "raw_response_sha256": hashlib.sha256(raw).hexdigest(),
        "collector_discovery_latency_ms": latency_ms,
    }


async def execute_scenario(scenario: dict) -> tuple[dict, list[dict]]:
    initial = await clean_reference(2)
    references = {"initial": initial}
    install_plan(scenario)
    observations = []

    tick = 0
    for _ in range(scenario["public_lifecycle"]["pre_ticks"]):
        observations.append(await collect_tick(tick, "steady_pre"))
        tick += 1
        await asyncio.sleep(0.015)

    active_count = 2
    for event in scenario["events"]:
        operation = event["operation"]
        slot = event["slot"]
        if operation == "stop":
            await stop_nf(slot)
            active_count -= 1
        elif operation == "start":
            await start_nf(slot)
            active_count += 1
        elif operation == "restart":
            await stop_nf(slot)
            await start_nf(slot)
        else:
            raise RuntimeError(f"unknown lifecycle operation {operation}")

        enable_hook()
        for _ in range(event["duration_ticks"]):
            observations.append(await collect_tick(tick, event["phase"]))
            tick += 1
            await asyncio.sleep(0.020)

        references[event["post_reference"]] = await clean_reference(active_count)

    enable_hook()
    for _ in range(scenario["public_lifecycle"]["post_ticks"]):
        observations.append(await collect_tick(tick, "steady_post"))
        tick += 1
        await asyncio.sleep(0.015)

    disable_hook()
    for _ in range(SOAK_TICKS):
        observations.append(await collect_tick(tick, "clean_soak"))
        tick += 1
        await asyncio.sleep(0.003)

    if tick != scenario["total_ticks"]:
        raise RuntimeError(f"scenario tick mismatch {tick} != {scenario['total_ticks']}")
    return references, observations


def post_json(url: str, doc: dict, *, token: str | None, timeout: float = 30):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url, data=canonical_bytes(doc), headers=headers, method="POST"
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read()), (
                time.perf_counter() - started
            ) * 1000
    except urllib.error.HTTPError as ex:
        body = ex.read()
        return ex.code, json.loads(body) if body else {}, (
            time.perf_counter() - started
        ) * 1000


def sign_package(package: dict) -> str:
    signature = PRIVATE_KEY.sign(
        canonical_bytes(package), ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode("ascii")


async def run_experiment(seed: int, challenge_nonce: str) -> dict:
    bootstrap = await s34.restart_testbed()
    if s34.count_projection(bootstrap) != (2, 2):
        raise RuntimeError("bootstrap did not reach two NSSF profiles")

    scenario, _ = build_scenario(seed, challenge_nonce)
    references, observations = await execute_scenario(scenario)

    nrf_log = s34.LOG_ROOT / "nrf.log"
    native_log = nrf_log.read_text(errors="replace") if nrf_log.exists() else ""
    mutation_count = native_log.count("STAGE37_NATIVE_NRF_RELATIONAL_MUTATION")
    if mutation_count != len(scenario["entries"]):
        raise RuntimeError(
            f"native mutation marker mismatch {mutation_count} != "
            f"{len(scenario['entries'])}"
        )

    sequence = next_sequence()
    package = {
        "stage": STAGE,
        "schema": "stage37-randomized-transition-telemetry-v1",
        "seed": seed,
        "challenge_nonce": challenge_nonce,
        "collector_sequence": sequence,
        "collector_service_revision": SERVICE_REVISION,
        "collector_public_key_sha256": PUBLIC_KEY_SHA256,
        "policy_sha256": POLICY_SHA256,
        "open5gs_ref": OPEN5GS_REF,
        "telemetry_origin": "external_open5gs_testbed",
        "lifecycle_plan": scenario["public_lifecycle"],
        "reference_states": references,
        "observations": observations,
        "native_nrf_source_sha256": hashlib.sha256(
            Path("/opt/stage37/stage37-nnrf-handler.c").read_bytes()
        ).hexdigest(),
        "attack_labels_in_package": False,
    }
    collector_signature = sign_package(package)
    request = {
        "telemetry_package": package,
        "collector_signature_base64": collector_signature,
    }

    unauth_status, _, unauth_ms = post_json(
        VERIFIER_A + "/verify", request, token=None, timeout=15
    )
    if unauth_status != 401:
        raise RuntimeError(
            f"verifier accepted unauthenticated collector: {unauth_status}"
        )

    status, verifier_result, verifier_latency_ms = post_json(
        VERIFIER_A + "/verify", request, token=VERIFIER_TOKEN, timeout=30
    )
    if status != 200:
        raise RuntimeError(f"verifier A failed HTTP {status}: {verifier_result}")

    replay_status, replay_doc, replay_latency_ms = post_json(
        VERIFIER_B + "/verify", request, token=VERIFIER_TOKEN, timeout=30
    )
    if replay_status not in (409, 422):
        raise RuntimeError(
            "cross-instance replay unexpectedly accepted: "
            f"{replay_status} {replay_doc}"
        )

    attack_ticks = {int(row["tick"]) for row in scenario["entries"]}
    labels = {
        "stage": STAGE,
        "seed": seed,
        "challenge_nonce": challenge_nonce,
        "topology_template_id": scenario["public_lifecycle"]["template_id"],
        "lifecycle_events": scenario["events"],
        "transition_attack_entries": scenario["entries"],
        "attack_ticks": sorted(attack_ticks),
        "attack_families": list(KINDS),
        "clean_soak_ticks": SOAK_TICKS,
        "total_ticks": len(observations),
        "native_mutation_marker_count": mutation_count,
        "private_plan_sha256": scenario["plan_sha256"],
        "schedule_secret_sha256": scenario["schedule_secret_sha256"],
        "labels_join_posthoc_only": True,
    }

    latencies = [
        float(row["collector_discovery_latency_ms"]) for row in observations
    ]
    return {
        "stage": STAGE,
        "seed": seed,
        "collector_package_sha256": hashlib.sha256(
            canonical_bytes(package)
        ).hexdigest(),
        "telemetry_package": package,
        "collector_signature_base64": collector_signature,
        "verifier_result": verifier_result,
        "private_labels": labels,
        "evidence": {
            "stage": STAGE,
            "seed": seed,
            "topology_template_id": scenario["public_lifecycle"]["template_id"],
            "attack_episode_count": len(scenario["entries"]),
            "total_observation_ticks": len(observations),
            "native_mutation_marker_count": mutation_count,
            "collector_public_key_sha256": PUBLIC_KEY_SHA256,
            "collector_service_revision": SERVICE_REVISION,
            "verifier_latency_ms": verifier_latency_ms,
            "unauthenticated_control_latency_ms": unauth_ms,
            "cross_instance_replay_status": replay_status,
            "cross_instance_replay_latency_ms": replay_latency_ms,
            "collector_discovery_latency_ms": {
                "mean": sum(latencies) / len(latencies),
                "max": max(latencies),
            },
            "scenario_variability": {
                "lifecycle_order_varies": True,
                "transition_target_varies": True,
                "phase_duration_varies": True,
                "attack_density_varies": True,
                "attack_family_varies": True,
                "mutation_variant_varies": True,
            },
        },
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Stage37RandomizedCollector/1.0"

    def _send(self, status: int, doc: dict) -> None:
        body = json.dumps(doc, sort_keys=True).encode("utf8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {
                "stage": STAGE,
                "status": "ok",
                "service_revision": SERVICE_REVISION,
                "policy_sha256": POLICY_SHA256,
                "collector_public_key_sha256": PUBLIC_KEY_SHA256,
                "open5gs_ref": OPEN5GS_REF,
                "telemetry_origin": "external_open5gs_testbed",
                "direct_verifier_transport": True,
                "scenario_generator": "randomized-topology-v1",
            })
            return
        if self.path == "/public-key":
            self._send(200, {
                "stage": STAGE,
                "public_key_pem": PUBLIC_KEY_PEM.decode("ascii"),
                "public_key_sha256": PUBLIC_KEY_SHA256,
            })
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/run":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("invalid body length")
            request = json.loads(self.rfile.read(length))
            if int(request.get("stage", -1)) != STAGE:
                raise ValueError("stage mismatch")
            if request.get("policy_sha256", "").lower() != POLICY_SHA256:
                raise PermissionError("policy digest not approved")
            seed = int(request["seed"])
            nonce = str(request["challenge_nonce"])
            if len(nonce) < 32 or len(nonce) > 256:
                raise ValueError("invalid challenge nonce")

            if not RUN_LOCK.acquire(blocking=False):
                self._send(429, {"error": "collector busy"})
                return
            try:
                result = asyncio.run(run_experiment(seed, nonce))
            finally:
                RUN_LOCK.release()
            self._send(200, result)
        except PermissionError as ex:
            self._send(403, {"error": str(ex)})
        except Exception as ex:
            print(
                "STAGE37_COLLECTOR_ERROR "
                f"{type(ex).__name__}: {ex}", flush=True
            )
            self._send(422, {"error": f"{type(ex).__name__}: {ex}"})

    def log_message(self, fmt, *args):
        print("STAGE37_COLLECTOR_HTTP", fmt % args, flush=True)


def main():
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(
        "STAGE37_RANDOMIZED_COLLECTOR_READY "
        f"port={port} policy={POLICY_SHA256} key={PUBLIC_KEY_SHA256} "
        f"revision={SERVICE_REVISION}",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        s34.stop_processes()


if __name__ == "__main__":
    main()
