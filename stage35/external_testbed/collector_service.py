"""Stage 35 external transition/churn collector.

This service reuses the proven Stage-34 external Open5GS testbed helpers but
changes the experiment protocol:

- relational attacks are injected while legitimate NSSF stop/start/restart
  transitions are converging;
- clean old/new transition endpoint states are signed into the package;
- a long clean post-transition soak is collected;
- the collector sends the signed package directly to authenticated verifier A;
- the same package is replayed to verifier B to prove freshness state is
  outside either verifier process;
- GitHub receives only signed evidence/verdict plus private labels for post-hoc
  scoring. It does not transport telemetry to the verifier.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

STAGE = 35
POLICY_SHA256 = os.environ["STAGE35_POLICY_SHA256"].lower()
SERVICE_REVISION = os.environ.get("STAGE35_COLLECTOR_REVISION", "unrecorded")
VERIFIER_A = os.environ["STAGE35_VERIFIER_A_ENDPOINT"].rstrip("/")
VERIFIER_B = os.environ["STAGE35_VERIFIER_B_ENDPOINT"].rstrip("/")
VERIFIER_TOKEN = os.environ["STAGE35_COLLECTOR_TO_VERIFIER_TOKEN"]
MAX_BODY = 128_000
SOAK_TICKS = 300

private_pem = os.environ["STAGE35_COLLECTOR_PRIVATE_KEY_PEM"].encode("utf8")
PRIVATE_KEY = serialization.load_pem_private_key(private_pem, password=None)
if not isinstance(PRIVATE_KEY, ec.EllipticCurvePrivateKey):
    raise RuntimeError("collector private key must be EC")
PUBLIC_KEY_PEM = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY_PEM).hexdigest()

# Stage34 helper import requires its startup environment. The helper's HTTP
# server is not started; only local Open5GS/process/projection functions are
# reused.
os.environ.setdefault("STAGE34_POLICY_SHA256", POLICY_SHA256)
os.environ.setdefault("STAGE34_COLLECTOR_REVISION", SERVICE_REVISION)
os.environ.setdefault(
    "STAGE34_COLLECTOR_PRIVATE_KEY_PEM", private_pem.decode("utf8")
)
_spec = importlib.util.spec_from_file_location(
    "stage34_collector_helpers",
    "/opt/stage35/stage34_collector_service.py",
)
s34 = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(s34)

RUN_LOCK = threading.Lock()
SEQUENCE_LOCK = threading.Lock()
COLLECTOR_SEQUENCE = 0

ATTACK_ENTRIES = [
    {"tick": 5, "kind": "endpoint_substitution", "phase": "stop_transition"},
    {"tick": 6, "kind": "service_injection", "phase": "stop_transition"},
    {"tick": 8, "kind": "identity_replacement", "phase": "stop_transition"},
    {"tick": 10, "kind": "endpoint_substitution", "phase": "stop_transition"},
    {"tick": 13, "kind": "service_injection", "phase": "start_transition"},
    {"tick": 14, "kind": "identity_replacement", "phase": "start_transition"},
    {"tick": 16, "kind": "endpoint_substitution", "phase": "start_transition"},
    {"tick": 18, "kind": "service_injection", "phase": "start_transition"},
    {"tick": 21, "kind": "endpoint_substitution", "phase": "restart_transition"},
    {"tick": 22, "kind": "identity_replacement", "phase": "restart_transition"},
    {"tick": 24, "kind": "service_injection", "phase": "restart_transition"},
    {"tick": 26, "kind": "identity_replacement", "phase": "restart_transition"},
]


def canonical_bytes(doc) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def next_sequence() -> int:
    global COLLECTOR_SEQUENCE
    with SEQUENCE_LOCK:
        COLLECTOR_SEQUENCE += 1
        return COLLECTOR_SEQUENCE


def post_json(url: str, doc: dict, *, token: str | None, timeout: float = 30):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url,
        data=canonical_bytes(doc),
        headers=headers,
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            elapsed = (time.perf_counter() - started) * 1000
            return response.status, json.loads(response.read()), elapsed
    except urllib.error.HTTPError as ex:
        elapsed = (time.perf_counter() - started) * 1000
        body = ex.read()
        return ex.code, json.loads(body) if body else {}, elapsed


def get_json(url: str, timeout: float = 15) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read())


def install_transition_plan() -> None:
    plan_text = "".join(
        f"{row['tick']}\t{row['kind']}\t1\n" for row in ATTACK_ENTRIES
    )
    s34.PLAN_ROOT.mkdir(parents=True, exist_ok=True)
    (s34.PLAN_ROOT / "plan.tsv").write_text(plan_text, encoding="utf8")
    os.chmod(s34.PLAN_ROOT / "plan.tsv", 0o400)
    (s34.PLAN_ROOT / "enabled").touch()


def enable_hook() -> None:
    (s34.PLAN_ROOT / "enabled").touch()


def disable_hook() -> None:
    (s34.PLAN_ROOT / "enabled").unlink(missing_ok=True)


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
    s34.start_process(
        name,
        "/src/open5gs/build/src/nssf/open5gs-nssfd",
        config,
    )
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
    # Repeat to reject transient convergence states.
    for _ in range(3):
        obj, _ = await s34.discover()
        check = s34.relational_projection(obj)
        if canonical_bytes(check) != canonical_bytes(projection):
            raise RuntimeError("transition endpoint reference not stable")
        await asyncio.sleep(0.02)
    return projection


async def collect_tick(tick: int, phase: str) -> dict:
    started = time.perf_counter()
    obj, raw = await s34.discover()
    discovery_ms = (time.perf_counter() - started) * 1000
    projection = s34.relational_projection(obj)
    count, registered = s34.count_projection(projection)
    return {
        "tick": tick,
        "phase": phase,
        "projection": projection,
        "legacy_nssf_count": count,
        "legacy_registered_count": registered,
        "raw_response_sha256": hashlib.sha256(raw).hexdigest(),
        "collector_discovery_latency_ms": discovery_ms,
    }


async def collect_transition_block() -> tuple[dict, list[dict]]:
    initial = await clean_reference(2)
    install_transition_plan()

    observations = []
    # Four pre-transition clean points. The hook is enabled but no plan entry
    # exists for these ticks.
    for tick in range(0, 4):
        observations.append(await collect_tick(tick, "steady_pre"))

    # Stop nssf2 and observe convergence with four count-preserving mutations.
    await stop_nf("nssf2")
    for tick in range(4, 12):
        observations.append(await collect_tick(tick, "stop_transition"))
        await asyncio.sleep(0.025)

    after_stop = await clean_reference(1)

    # Re-enable the same native plan. Eligible hook tick remains 12 because
    # clean reference queries occurred while the hook was disabled.
    enable_hook()
    await start_nf("nssf2")
    for tick in range(12, 20):
        observations.append(await collect_tick(tick, "start_transition"))
        await asyncio.sleep(0.025)

    after_start = await clean_reference(2)

    enable_hook()
    await stop_nf("nssf1")
    await start_nf("nssf1")
    for tick in range(20, 28):
        observations.append(await collect_tick(tick, "restart_transition"))
        await asyncio.sleep(0.025)

    after_restart = await clean_reference(2)

    # Steady recovery control.
    for tick in range(28, 32):
        observations.append(await collect_tick(tick, "steady_post"))

    # Long clean soak with the fault hook disabled.
    disable_hook()
    for offset in range(SOAK_TICKS):
        tick = 32 + offset
        observations.append(await collect_tick(tick, "clean_soak"))
        await asyncio.sleep(0.004)

    refs = {
        "initial": initial,
        "after_stop": after_stop,
        "after_start": after_start,
        "after_restart": after_restart,
    }
    return refs, observations


def sign_package(package: dict) -> str:
    signature = PRIVATE_KEY.sign(
        canonical_bytes(package), ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode("ascii")


async def run_experiment(seed: int, challenge_nonce: str) -> dict:
    bootstrap = await s34.restart_testbed()
    if s34.count_projection(bootstrap) != (2, 2):
        raise RuntimeError("Stage35 bootstrap did not reach two NSSF profiles")

    references, observations = await collect_transition_block()

    native_log_path = s34.LOG_ROOT / "nrf.log"
    native_log = (
        native_log_path.read_text(errors="replace")
        if native_log_path.exists()
        else ""
    )
    mutation_count = native_log.count(
        "STAGE34_NATIVE_NRF_RELATIONAL_MUTATION"
    )
    if mutation_count != len(ATTACK_ENTRIES):
        raise RuntimeError(
            f"native mutation marker mismatch {mutation_count} != "
            f"{len(ATTACK_ENTRIES)}"
        )

    sequence = next_sequence()
    package = {
        "stage": STAGE,
        "schema": "stage35-transition-relational-telemetry-v1",
        "seed": seed,
        "challenge_nonce": challenge_nonce,
        "collector_sequence": sequence,
        "collector_service_revision": SERVICE_REVISION,
        "collector_public_key_sha256": PUBLIC_KEY_SHA256,
        "policy_sha256": POLICY_SHA256,
        "open5gs_ref": "v2.7.6",
        "telemetry_origin": "external_open5gs_testbed",
        "reference_states": references,
        "observations": observations,
        "native_nrf_source_sha256": hashlib.sha256(
            Path("/opt/stage35/stage34-nnrf-handler.c").read_bytes()
        ).hexdigest(),
        "attack_labels_in_package": False,
    }
    collector_signature = sign_package(package)
    request = {
        "telemetry_package": package,
        "collector_signature_base64": collector_signature,
    }

    # Authentication negative control: unauthenticated verifier access must fail
    # before the real package is submitted.
    unauth_status, _, unauth_ms = post_json(
        VERIFIER_A + "/verify", request, token=None, timeout=15
    )
    if unauth_status != 401:
        raise RuntimeError(
            f"verifier accepted unauthenticated collector: {unauth_status}"
        )

    status, verifier_result, verifier_latency_ms = post_json(
        VERIFIER_A + "/verify",
        request,
        token=VERIFIER_TOKEN,
        timeout=30,
    )
    if status != 200:
        raise RuntimeError(
            f"verifier A failed HTTP {status}: {verifier_result}"
        )

    # Cross-instance replay: verifier B has not seen the request locally, so
    # only the external anchor can cause this rejection.
    replay_status, replay_doc, replay_latency_ms = post_json(
        VERIFIER_B + "/verify",
        request,
        token=VERIFIER_TOKEN,
        timeout=30,
    )
    if replay_status not in (409, 422):
        raise RuntimeError(
            "cross-instance replay unexpectedly accepted: "
            f"{replay_status} {replay_doc}"
        )

    attack_ticks = {int(row["tick"]) for row in ATTACK_ENTRIES}
    labels = {
        "stage": STAGE,
        "seed": seed,
        "challenge_nonce": challenge_nonce,
        "transition_attack_entries": ATTACK_ENTRIES,
        "attack_ticks": sorted(attack_ticks),
        "transition_windows": {
            "stop_transition": [4, 11],
            "start_transition": [12, 19],
            "restart_transition": [20, 27],
        },
        "clean_soak_ticks": SOAK_TICKS,
        "total_ticks": len(observations),
        "native_mutation_marker_count": mutation_count,
        "labels_join_posthoc_only": True,
    }

    discovery_latencies = [
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
            "policy_sha256": POLICY_SHA256,
            "collector_public_key_sha256": PUBLIC_KEY_SHA256,
            "collector_service_revision": SERVICE_REVISION,
            "collector_sequence": sequence,
            "verifier_a_endpoint": VERIFIER_A,
            "verifier_b_endpoint": VERIFIER_B,
            "unauthenticated_request_rejected": True,
            "unauthenticated_request_latency_ms": unauth_ms,
            "authenticated_verifier_status": status,
            "authenticated_verifier_latency_ms": verifier_latency_ms,
            "cross_instance_replay_rejected": True,
            "cross_instance_replay_status": replay_status,
            "cross_instance_replay_latency_ms": replay_latency_ms,
            "collector_discovery_latency_ms": {
                "count": len(discovery_latencies),
                "p50": statistics.median(discovery_latencies),
                "max": max(discovery_latencies),
                "mean": statistics.mean(discovery_latencies),
            },
            "github_created_telemetry_rows": False,
            "collector_sent_telemetry_directly_to_verifier": True,
        },
    }


def percentile(values: list[float], q: float) -> float:
    if not values:
        raise ValueError("empty percentile input")
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lower = int(pos)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = pos - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


async def benchmark(iterations: int = 100) -> dict:
    # Benchmark uses a fresh clean testbed and one-observation signed packages.
    baseline = await s34.restart_testbed()
    latencies = []
    successes = 0
    statuses = {}

    for i in range(iterations):
        sequence = next_sequence()
        nonce = secrets.token_hex(32)
        package = {
            "stage": STAGE,
            "schema": "stage35-transition-relational-telemetry-v1",
            "seed": 350000 + i,
            "challenge_nonce": nonce,
            "collector_sequence": sequence,
            "collector_service_revision": SERVICE_REVISION,
            "collector_public_key_sha256": PUBLIC_KEY_SHA256,
            "policy_sha256": POLICY_SHA256,
            "open5gs_ref": "v2.7.6",
            "telemetry_origin": "external_open5gs_testbed",
            "reference_states": {
                "initial": baseline,
                "after_stop": baseline,
                "after_start": baseline,
                "after_restart": baseline,
            },
            "observations": [
                {
                    "tick": 0,
                    "phase": "steady_pre",
                    "projection": baseline,
                    "legacy_nssf_count": 2,
                    "legacy_registered_count": 2,
                    "raw_response_sha256": "benchmark",
                    "collector_discovery_latency_ms": 0.0,
                }
            ],
            "native_nrf_source_sha256": hashlib.sha256(
                Path("/opt/stage35/stage34-nnrf-handler.c").read_bytes()
            ).hexdigest(),
            "attack_labels_in_package": False,
        }
        request = {
            "telemetry_package": package,
            "collector_signature_base64": sign_package(package),
        }
        status, _, elapsed = post_json(
            VERIFIER_A + "/verify",
            request,
            token=VERIFIER_TOKEN,
            timeout=30,
        )
        statuses[str(status)] = statuses.get(str(status), 0) + 1
        latencies.append(elapsed)
        successes += int(status == 200)

    elapsed_s = sum(latencies) / 1000.0
    return {
        "stage": STAGE,
        "iterations": iterations,
        "successes": successes,
        "availability": successes / iterations,
        "status_counts": statuses,
        "latency_ms": {
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
            "max": max(latencies),
            "mean": statistics.mean(latencies),
        },
        "sequential_throughput_requests_per_second": (
            iterations / elapsed_s if elapsed_s > 0 else None
        ),
        "benchmark_mode": "sequential_full_signature_and_anchor_path",
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Stage35TransitionCollector/1.0"

    def send_json(self, status: int, doc: dict) -> None:
        body = json.dumps(doc, sort_keys=True).encode("utf8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(
                200,
                {
                    "stage": STAGE,
                    "status": "ok",
                    "policy_sha256": POLICY_SHA256,
                    "collector_public_key_sha256": PUBLIC_KEY_SHA256,
                    "service_revision": SERVICE_REVISION,
                    "telemetry_origin": "external_open5gs_testbed",
                    "direct_verifier_transport": True,
                },
            )
            return
        if self.path == "/public-key":
            self.send_json(
                200,
                {
                    "stage": STAGE,
                    "public_key_pem": PUBLIC_KEY_PEM.decode("ascii"),
                    "public_key_sha256": PUBLIC_KEY_SHA256,
                },
            )
            return
        self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/run", "/benchmark"):
            self.send_json(404, {"error": "not found"})
            return
        if not RUN_LOCK.acquire(blocking=False):
            self.send_json(429, {"error": "collector busy"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("invalid body length")
            request = json.loads(self.rfile.read(length))
            if request.get("policy_sha256", "").lower() != POLICY_SHA256:
                raise PermissionError("policy mismatch")

            if self.path == "/run":
                if int(request.get("stage", -1)) != STAGE:
                    raise ValueError("stage mismatch")
                seed = int(request["seed"])
                nonce = str(request["challenge_nonce"])
                if len(nonce) < 32 or len(nonce) > 256:
                    raise ValueError("invalid challenge nonce")
                result = asyncio.run(run_experiment(seed, nonce))
            else:
                result = asyncio.run(
                    benchmark(int(request.get("iterations", 100)))
                )

            self.send_json(200, result)
        except PermissionError as ex:
            self.send_json(403, {"error": str(ex)})
        except Exception as ex:
            print(
                "STAGE35_COLLECTOR_ERROR "
                f"{type(ex).__name__}: {ex}",
                flush=True,
            )
            self.send_json(422, {"error": f"{type(ex).__name__}: {ex}"})
        finally:
            RUN_LOCK.release()

    def log_message(self, fmt, *args):
        print("STAGE35_COLLECTOR_HTTP", fmt % args, flush=True)


def main():
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(
        "STAGE35_TRANSITION_COLLECTOR_READY "
        f"port={port} policy={POLICY_SHA256} key={PUBLIC_KEY_SHA256} "
        f"revision={SERVICE_REVISION}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
