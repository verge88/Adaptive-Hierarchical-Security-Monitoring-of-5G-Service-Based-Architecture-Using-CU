"""Stage 34 external Open5GS testbed and signed collector.

The Open5GS NRF/SCP/NSSF processes, attack-plan realization, SBI collection,
and telemetry signing execute inside this external Render container. GitHub
Actions never creates the telemetry rows: it receives an already signed package.

The private attack labels are returned separately for post-hoc audit and are
not required by the external relational verifier.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import random
import secrets
import signal
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset

STAGE = 34
OPEN5GS_REF = "v2.7.6"
NRF_URL = "http://127.0.0.10:80"
SCP_URL = "http://127.0.0.11:80"
NRF_TARGET = "http://127.0.0.10:80"
NRF_PATH = "/nnrf-disc/v1/nf-instances?target-nf-type=NSSF&requester-nf-type=AMF"
CONFIG_ROOT = Path("/opt/stage34")
PLAN_ROOT = Path("/run/stage34")
LOG_ROOT = Path("/var/log/open5gs")
MAX_BODY = 128_000

KINDS = (
    "identity_swap",
    "identity_replacement",
    "endpoint_substitution",
    "service_injection",
)
EPISODES = 24
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
GAP_RANGE = (3, 6)
BASELINE_SAMPLES = 12

APPROVED_POLICY_SHA256 = os.environ["STAGE34_POLICY_SHA256"].lower()
SERVICE_REVISION = os.environ.get("STAGE34_COLLECTOR_REVISION", "unrecorded")
_private_pem = os.environ.get("STAGE34_COLLECTOR_PRIVATE_KEY_PEM")
if not _private_pem:
    raise RuntimeError("STAGE34_COLLECTOR_PRIVATE_KEY_PEM is required")
PRIVATE_KEY = serialization.load_pem_private_key(
    _private_pem.encode("utf8"), password=None
)
if not isinstance(PRIVATE_KEY, ec.EllipticCurvePrivateKey):
    raise RuntimeError("collector key must be an EC private key")
PUBLIC_KEY_PEM = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY_PEM).hexdigest()

RUN_LOCK = threading.Lock()
COLLECTOR_SEQUENCE = 0
PROCESSES: dict[str, subprocess.Popen] = {}


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def balanced(values: tuple[str, ...], copies: int, rng: random.Random) -> list[str]:
    result = list(values) * copies
    rng.shuffle(result)
    return result


def build_schedule(seed_material: str) -> dict:
    digest = hashlib.sha256(seed_material.encode("utf8")).digest()
    rng = random.Random(int.from_bytes(digest, "big"))

    kinds = balanced(KINDS, 6, rng)
    durations = balanced(("short", "medium", "long"), 8, rng)
    densities = balanced(("low", "medium", "high"), 8, rng)

    cursor = 0
    episodes = []
    entries = []
    for index in range(EPISODES):
        duration_bin = durations[index]
        density_bin = densities[index]
        kind = kinds[index]
        duration = rng.randint(*DURATION_RANGES[duration_bin])
        lo, hi = DENSITY_RANGES[density_bin]
        target = rng.uniform(lo, hi)
        mutation_count = max(1, min(duration, round(duration * target)))
        offsets = sorted(rng.sample(range(duration), mutation_count))

        start = cursor
        end = start + duration
        mutation_ticks = [start + offset for offset in offsets]
        for tick in mutation_ticks:
            entries.append({"tick": tick, "kind": kind, "parameter": 1})

        episodes.append(
            {
                "episode": index,
                "kind": kind,
                "duration_bin": duration_bin,
                "density_bin": density_bin,
                "duration_ticks": duration,
                "realized_density": mutation_count / duration,
                "start_tick": start,
                "end_tick": end,
                "mutation_ticks": mutation_ticks,
            }
        )
        cursor = end + rng.randint(*GAP_RANGE)

    plan_text = "".join(
        f"{row['tick']}\t{row['kind']}\t{row['parameter']}\n"
        for row in entries
    )
    return {
        "episodes": episodes,
        "entries": entries,
        "total_ticks": cursor,
        "plan_text": plan_text,
        "plan_sha256": hashlib.sha256(plan_text.encode()).hexdigest(),
    }


def normalize_service(service: dict) -> dict:
    versions = []
    for row in service.get("versions", []) if isinstance(service.get("versions"), list) else []:
        if isinstance(row, dict):
            versions.append(
                {
                    "apiVersionInUri": row.get("apiVersionInUri"),
                    "apiFullVersion": row.get("apiFullVersion"),
                }
            )
    versions.sort(key=lambda x: json.dumps(x, sort_keys=True))

    endpoints = []
    for row in service.get("ipEndPoints", []) if isinstance(service.get("ipEndPoints"), list) else []:
        if isinstance(row, dict):
            endpoints.append(
                {
                    "ipv4Address": row.get("ipv4Address"),
                    "ipv6Address": row.get("ipv6Address"),
                    "transport": row.get("transport"),
                    "port": row.get("port"),
                }
            )
    endpoints.sort(key=lambda x: json.dumps(x, sort_keys=True))

    return {
        "serviceInstanceId": service.get("serviceInstanceId"),
        "serviceName": service.get("serviceName"),
        "scheme": service.get("scheme"),
        "nfServiceStatus": service.get("nfServiceStatus"),
        "versions": versions,
        "ipEndPoints": endpoints,
    }


def relational_projection(obj: dict) -> dict:
    instances = obj.get("nfInstances")
    if not isinstance(instances, list):
        raise ValueError("NRF discovery lacks nfInstances")

    result: dict[str, dict] = {}
    duplicate_ids = []
    for profile in instances:
        if not isinstance(profile, dict) or profile.get("nfType") != "NSSF":
            continue
        nf_id = profile.get("nfInstanceId")
        if not isinstance(nf_id, str):
            raise ValueError("NSSF profile lacks nfInstanceId")
        key = nf_id.lower()
        if key in result:
            duplicate_ids.append(key)

        services = []
        if isinstance(profile.get("nfServices"), list):
            services = [
                normalize_service(service)
                for service in profile["nfServices"]
                if isinstance(service, dict)
            ]
            services.sort(key=lambda x: json.dumps(x, sort_keys=True))

        ipv4 = profile.get("ipv4Addresses")
        ipv4_values = sorted(
            str(v) for v in ipv4
        ) if isinstance(ipv4, list) else []

        result[key] = {
            "nfType": profile.get("nfType"),
            "nfStatus": profile.get("nfStatus"),
            "fqdn": profile.get("fqdn"),
            "ipv4Addresses": ipv4_values,
            "nfServices": services,
        }

    return {
        "profiles": {key: result[key] for key in sorted(result)},
        "duplicateIds": sorted(duplicate_ids),
    }


def count_projection(projection: dict) -> tuple[int, int]:
    profiles = projection["profiles"]
    count = len(profiles)
    registered = sum(
        1 for row in profiles.values()
        if row.get("nfStatus") == "REGISTERED"
    )
    return count, registered


async def h2_exchange(base: str, path: str, *, target: str | None = None, timeout: float = 5.0):
    url = urlsplit(base)
    if url.scheme != "http" or not url.hostname:
        raise ValueError("stage34 external testbed uses local h2c only")

    async def once():
        reader, writer = await asyncio.open_connection(url.hostname, url.port or 80)
        conn = H2Connection(
            H2Configuration(client_side=True, header_encoding="utf-8")
        )
        body = bytearray()
        status = None
        try:
            conn.initiate_connection()
            stream = conn.get_next_available_stream_id()
            headers = [
                (":method", "GET"),
                (":scheme", "http"),
                (":authority", url.netloc),
                (":path", path),
                ("accept", "application/json"),
                ("user-agent", "AMF-Stage34-External-Collector"),
            ]
            if target is not None:
                headers.append(("3gpp-sbi-target-apiroot", target))
            conn.send_headers(stream, headers, end_stream=True)
            writer.write(conn.data_to_send())
            await writer.drain()

            while True:
                chunk = await reader.read(65535)
                if not chunk:
                    raise ConnectionError("h2 peer closed early")
                for event in conn.receive_data(chunk):
                    if isinstance(event, ResponseReceived) and event.stream_id == stream:
                        status = int(dict(event.headers)[":status"])
                    elif isinstance(event, DataReceived) and event.stream_id == stream:
                        body.extend(event.data)
                        conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, StreamReset) and event.stream_id == stream:
                        raise ConnectionError("h2 stream reset")
                    elif isinstance(event, StreamEnded) and event.stream_id == stream:
                        if status is None:
                            raise ConnectionError("missing h2 status")
                        return status, bytes(body)
                outbound = conn.data_to_send()
                if outbound:
                    writer.write(outbound)
                    await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    return await asyncio.wait_for(once(), timeout)


async def discover() -> tuple[dict, bytes]:
    status, body = await h2_exchange(
        SCP_URL, NRF_PATH, target=NRF_TARGET, timeout=5
    )
    if status != 200:
        raise RuntimeError(f"NRF discovery via native SCP returned {status}")
    return json.loads(body), body


def stop_processes() -> None:
    global PROCESSES
    for proc in PROCESSES.values():
        if proc.poll() is None:
            proc.terminate()
    deadline = time.time() + 4
    for proc in PROCESSES.values():
        while proc.poll() is None and time.time() < deadline:
            time.sleep(0.05)
        if proc.poll() is None:
            proc.kill()
    PROCESSES = {}


def start_process(name: str, binary: str, config: str) -> subprocess.Popen:
    log_path = LOG_ROOT / f"stage34-{name}-stdout.log"
    handle = open(log_path, "ab", buffering=0)
    proc = subprocess.Popen(
        [binary, "-c", str(CONFIG_ROOT / config)],
        stdout=handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    PROCESSES[name] = proc
    return proc


def diagnostic_state() -> str:
    parts = []
    for name, proc in PROCESSES.items():
        parts.append(f"{name}:poll={proc.poll()}")
        path = LOG_ROOT / f"stage34-{name}-stdout.log"
        if path.exists():
            tail = path.read_text(errors="replace")[-1200:]
            parts.append(f"{name}:tail={tail}")
    return " | ".join(parts)


async def wait_ready() -> dict:
    last = ""
    for _ in range(120):
        try:
            obj, _ = await discover()
            projection = relational_projection(obj)
            count, registered = count_projection(projection)
            if count == 2 and registered == 2:
                return projection
            last = f"projection={projection}"
        except Exception as ex:
            last = f"{type(ex).__name__}: {ex}"
        await asyncio.sleep(0.5)
    raise RuntimeError(
        "external Open5GS testbed failed readiness: "
        + last[-600:]
        + " diagnostics="
        + diagnostic_state()
    )


async def restart_testbed() -> dict:
    stop_processes()
    PLAN_ROOT.mkdir(parents=True, exist_ok=True)
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    for p in PLAN_ROOT.glob("*"):
        p.unlink(missing_ok=True)
    for p in LOG_ROOT.glob("stage34-*.log"):
        p.unlink(missing_ok=True)

    start_process("nrf", "/src/open5gs/build/src/nrf/open5gs-nrfd", "nrf.yaml")
    await asyncio.sleep(0.4)
    start_process("scp", "/src/open5gs/build/src/scp/open5gs-scpd", "scp.yaml")
    start_process("nssf1", "/src/open5gs/build/src/nssf/open5gs-nssfd", "nssf1.yaml")
    start_process("nssf2", "/src/open5gs/build/src/nssf/open5gs-nssfd", "nssf2.yaml")
    return await wait_ready()


async def capture_clean_baseline() -> dict:
    projections = []
    raw_hashes = []
    for _ in range(BASELINE_SAMPLES):
        obj, raw = await discover()
        projections.append(relational_projection(obj))
        raw_hashes.append(hashlib.sha256(raw).hexdigest())
        await asyncio.sleep(0.03)

    canonical = [canonical_bytes(row) for row in projections]
    if any(row != canonical[0] for row in canonical[1:]):
        raise RuntimeError("relational clean baseline was not stable")
    count, registered = count_projection(projections[0])
    if (count, registered) != (2, 2):
        raise RuntimeError("clean baseline is not two REGISTERED NSSF profiles")
    return {
        "projection": projections[0],
        "sample_count": BASELINE_SAMPLES,
        "raw_response_sha256": raw_hashes,
        "count": count,
        "registered": registered,
    }


def install_plan(schedule: dict) -> None:
    PLAN_ROOT.mkdir(parents=True, exist_ok=True)
    (PLAN_ROOT / "plan.tsv").write_text(
        schedule["plan_text"], encoding="utf8"
    )
    os.chmod(PLAN_ROOT / "plan.tsv", 0o400)
    (PLAN_ROOT / "enabled").touch()


async def collect_observations(total_ticks: int, baseline: dict) -> list[dict]:
    observations = []
    baseline_count = int(baseline["count"])
    baseline_registered = int(baseline["registered"])

    for tick in range(total_ticks):
        obj, raw = await discover()
        projection = relational_projection(obj)
        count, registered = count_projection(projection)
        # The Stage-34 attack families are preregistered to preserve the two
        # legacy invariants. Any violation invalidates the run.
        if count != baseline_count or registered != baseline_registered:
            raise RuntimeError(
                "count-preserving Stage34 invariant violated "
                f"at tick {tick}: {(count, registered)}"
            )
        observations.append(
            {
                "tick": tick,
                "projection": projection,
                "legacy_nssf_count": count,
                "legacy_registered_count": registered,
                "raw_response_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        await asyncio.sleep(0.015)
    return observations


async def run_experiment(seed: int, challenge_nonce: str) -> dict:
    global COLLECTOR_SEQUENCE

    bootstrap = await restart_testbed()
    baseline = await capture_clean_baseline()
    if canonical_bytes(bootstrap) != canonical_bytes(baseline["projection"]):
        raise RuntimeError("readiness projection differs from frozen baseline")

    schedule_secret = secrets.token_hex(32)
    schedule = build_schedule(f"{seed}:{challenge_nonce}:{schedule_secret}")
    install_plan(schedule)
    observations = await collect_observations(
        schedule["total_ticks"], baseline
    )

    nrf_log = (LOG_ROOT / "nrf.log")
    native_log = nrf_log.read_text(errors="replace") if nrf_log.exists() else ""
    marker_count = native_log.count("STAGE34_NATIVE_NRF_RELATIONAL_MUTATION")
    if marker_count != len(schedule["entries"]):
        raise RuntimeError(
            f"native mutation log mismatch {marker_count} != "
            f"{len(schedule['entries'])}"
        )

    COLLECTOR_SEQUENCE += 1
    package = {
        "stage": STAGE,
        "schema": "stage34-external-relational-telemetry-v1",
        "seed": seed,
        "challenge_nonce": challenge_nonce,
        "collector_sequence": COLLECTOR_SEQUENCE,
        "collector_service_revision": SERVICE_REVISION,
        "collector_public_key_sha256": PUBLIC_KEY_SHA256,
        "policy_sha256": APPROVED_POLICY_SHA256,
        "open5gs_ref": OPEN5GS_REF,
        "consumer_path": "native_open5gs_scp_to_instrumented_native_nrf",
        "baseline": baseline,
        "observations": observations,
        "native_nrf_source_sha256": hashlib.sha256(
            Path("/opt/stage34/stage34-nnrf-handler.c").read_bytes()
        ).hexdigest(),
        "attack_labels_in_package": False,
    }
    package_sha = hashlib.sha256(canonical_bytes(package)).hexdigest()
    signature = PRIVATE_KEY.sign(
        canonical_bytes(package), ec.ECDSA(hashes.SHA256())
    )

    labels = {
        "stage": STAGE,
        "seed": seed,
        "challenge_nonce": challenge_nonce,
        "episodes": schedule["episodes"],
        "private_plan_entries": schedule["entries"],
        "private_plan_sha256": schedule["plan_sha256"],
        "schedule_secret_sha256": hashlib.sha256(
            schedule_secret.encode()
        ).hexdigest(),
        "total_ticks": schedule["total_ticks"],
        "native_mutation_marker_count": marker_count,
        "attack_families": list(KINDS),
        "count_preserving_by_design": True,
        "labels_join_posthoc_only": True,
    }

    return {
        "telemetry_package": package,
        "telemetry_package_sha256": package_sha,
        "collector_signature_base64": base64.b64encode(signature).decode("ascii"),
        "private_labels": labels,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Stage34ExternalCollector/1.0"

    def _send(self, status: int, doc: dict) -> None:
        body = json.dumps(doc, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(
                200,
                {
                    "stage": STAGE,
                    "status": "ok",
                    "service_revision": SERVICE_REVISION,
                    "policy_sha256": APPROVED_POLICY_SHA256,
                    "collector_public_key_sha256": PUBLIC_KEY_SHA256,
                    "open5gs_ref": OPEN5GS_REF,
                    "telemetry_origin": "external_open5gs_testbed",
                },
            )
            return
        if self.path == "/public-key":
            self._send(
                200,
                {
                    "stage": STAGE,
                    "public_key_pem": PUBLIC_KEY_PEM.decode("ascii"),
                    "public_key_sha256": PUBLIC_KEY_SHA256,
                },
            )
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
            if request.get("policy_sha256", "").lower() != APPROVED_POLICY_SHA256:
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
                "STAGE34_COLLECTOR_ERROR "
                f"{type(ex).__name__}: {ex}",
                flush=True,
            )
            self._send(422, {"error": f"{type(ex).__name__}: {ex}"})

    def log_message(self, fmt, *args):
        print("STAGE34_COLLECTOR_HTTP", fmt % args, flush=True)


def main():
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(
        "STAGE34_EXTERNAL_COLLECTOR_READY "
        f"port={port} policy={APPROVED_POLICY_SHA256} "
        f"key={PUBLIC_KEY_SHA256} revision={SERVICE_REVISION}",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        stop_processes()


if __name__ == "__main__":
    main()
