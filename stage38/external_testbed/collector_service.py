"""Stage 38 multi-NF Open5GS collector with NF-side witness."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import random
import secrets
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset

STAGE = 38
OPEN5GS_REF = "v2.7.6"
NRF_URL = "http://127.0.0.10:80"
SCP_URL = "http://127.0.0.11:80"
NRF_TARGET = "http://127.0.0.10:80"
CONFIG_ROOT = Path("/opt/stage38")
PLAN_ROOT = Path("/run/stage38")
WITNESS_DIR = PLAN_ROOT / "witness"
LOG_ROOT = Path("/var/log/open5gs")
WITNESS_ENDPOINT = "http://127.0.0.1:10001"
MAX_BODY = 128_000
CLEAN_SOAK_TICKS = 30

NF_TYPES = ("NSSF", "AUSF", "BSF", "UDM")
REQUESTER_BY_TYPE = {"NSSF": "AMF", "AUSF": "AMF", "BSF": "PCF", "UDM": "AMF"}
SLOTS = {
    "nssf1": {"type": "NSSF", "endpoint": "127.0.0.12", "config": "nssf1.yaml", "code": 1},
    "nssf2": {"type": "NSSF", "endpoint": "127.0.0.13", "config": "nssf2.yaml", "code": 2},
    "ausf1": {"type": "AUSF", "endpoint": "127.0.0.14", "config": "ausf1.yaml", "code": 3},
    "ausf2": {"type": "AUSF", "endpoint": "127.0.0.15", "config": "ausf2.yaml", "code": 4},
    "bsf1": {"type": "BSF", "endpoint": "127.0.0.16", "config": "bsf1.yaml", "code": 5},
    "bsf2": {"type": "BSF", "endpoint": "127.0.0.17", "config": "bsf2.yaml", "code": 6},
    "udm1": {"type": "UDM", "endpoint": "127.0.0.18", "config": "udm1.yaml", "code": 7},
    "udm2": {"type": "UDM", "endpoint": "127.0.0.19", "config": "udm2.yaml", "code": 8},
}
BINARIES = {
    "NSSF": "/src/open5gs/build/src/nssf/open5gs-nssfd",
    "AUSF": "/src/open5gs/build/src/ausf/open5gs-ausfd",
    "BSF": "/src/open5gs/build/src/bsf/open5gs-bsfd",
    "UDM": "/src/open5gs/build/src/udm/open5gs-udmd",
}
KINDS = (
    "identity_replacement",
    "endpoint_substitution",
    "service_injection",
    "fqdn_substitution",
    "nf_type_substitution",
    "compound_identity_service",
)
DENSITY_RANGES = {
    "low": (0.20, 0.35),
    "medium": (0.40, 0.55),
    "high": (0.60, 0.80),
}

POLICY_SHA256 = os.environ["STAGE38_POLICY_SHA256"].lower()
SERVICE_REVISION = os.environ.get("STAGE38_COLLECTOR_REVISION", "unrecorded")
VERIFIER_A = os.environ["STAGE38_VERIFIER_A_ENDPOINT"].rstrip("/")
VERIFIER_B = os.environ["STAGE38_VERIFIER_B_ENDPOINT"].rstrip("/")
VERIFIER_TOKEN = os.environ["STAGE38_COLLECTOR_TO_VERIFIER_TOKEN"]
WITNESS_TOKEN = os.environ["STAGE38_WITNESS_TOKEN"]

_private_pem = os.environ["STAGE38_COLLECTOR_PRIVATE_KEY_PEM"].encode()
PRIVATE_KEY = serialization.load_pem_private_key(_private_pem, password=None)
if not isinstance(PRIVATE_KEY, ec.EllipticCurvePrivateKey):
    raise RuntimeError("collector key must be EC")
PUBLIC_KEY_PEM = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY_PEM).hexdigest()

RUN_LOCK = threading.Lock()
SEQUENCE_LOCK = threading.Lock()
COLLECTOR_SEQUENCE = 0
PROCESSES: dict[str, subprocess.Popen] = {}
WITNESS_PROCESS: subprocess.Popen | None = None


def canonical_bytes(doc) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def next_sequence() -> int:
    global COLLECTOR_SEQUENCE
    with SEQUENCE_LOCK:
        COLLECTOR_SEQUENCE += 1
        return COLLECTOR_SEQUENCE


def normalize_service(service: dict) -> dict:
    versions = []
    for row in service.get("versions", []) if isinstance(service.get("versions"), list) else []:
        if isinstance(row, dict):
            versions.append({
                "apiVersionInUri": row.get("apiVersionInUri"),
                "apiFullVersion": row.get("apiFullVersion"),
            })
    versions.sort(key=lambda x: json.dumps(x, sort_keys=True))

    endpoints = []
    for row in service.get("ipEndPoints", []) if isinstance(service.get("ipEndPoints"), list) else []:
        if isinstance(row, dict):
            endpoints.append({
                "ipv4Address": row.get("ipv4Address"),
                "ipv6Address": row.get("ipv6Address"),
                "transport": row.get("transport"),
                "port": row.get("port"),
            })
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
    profiles = {}
    duplicate_ids = []
    for profile in instances:
        if not isinstance(profile, dict):
            continue
        nf_id = profile.get("nfInstanceId")
        if not isinstance(nf_id, str):
            raise ValueError("NF profile lacks nfInstanceId")
        key = nf_id.lower()
        if key in profiles:
            duplicate_ids.append(key)
        services = [
            normalize_service(s) for s in profile.get("nfServices", [])
            if isinstance(s, dict)
        ] if isinstance(profile.get("nfServices"), list) else []
        services.sort(key=lambda x: json.dumps(x, sort_keys=True))
        ipv4 = profile.get("ipv4Addresses")
        profiles[key] = {
            "nfType": profile.get("nfType"),
            "nfStatus": profile.get("nfStatus"),
            "fqdn": profile.get("fqdn"),
            "ipv4Addresses": sorted(str(v) for v in ipv4) if isinstance(ipv4, list) else [],
            "nfServices": services,
        }
    return {
        "profiles": {k: profiles[k] for k in sorted(profiles)},
        "duplicateIds": sorted(duplicate_ids),
    }


def state_counts(projection: dict) -> tuple[int, int]:
    profiles = projection["profiles"]
    return (
        len(profiles),
        sum(1 for row in profiles.values() if row.get("nfStatus") == "REGISTERED"),
    )


async def h2_exchange(base: str, path: str, *, target: str | None = None, timeout: float = 5.0):
    url = urlsplit(base)
    reader, writer = await asyncio.open_connection(url.hostname, url.port or 80)
    conn = H2Connection(H2Configuration(client_side=True, header_encoding="utf-8"))
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
            ("user-agent", "SCP"),
        ]
        if target is not None:
            headers.append(("3gpp-sbi-target-apiroot", target))
        conn.send_headers(stream, headers, end_stream=True)
        writer.write(conn.data_to_send())
        await writer.drain()
        while True:
            chunk = await asyncio.wait_for(reader.read(65535), timeout)
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


async def discover_type(nf_type: str) -> tuple[dict, bytes]:
    requester = REQUESTER_BY_TYPE[nf_type]
    path = (
        "/nnrf-disc/v1/nf-instances"
        f"?target-nf-type={nf_type}&requester-nf-type={requester}"
    )
    status, body = await h2_exchange(SCP_URL, path, target=NRF_TARGET)
    if status != 200:
        raise RuntimeError(f"NRF discovery {nf_type} returned {status}")
    return relational_projection(json.loads(body)), body


async def discover_all() -> tuple[dict, dict]:
    projections = {}
    hashes_by_type = {}
    for nf_type in NF_TYPES:
        projection, raw = await discover_type(nf_type)
        projections[nf_type] = projection
        hashes_by_type[nf_type] = hashlib.sha256(raw).hexdigest()
    return projections, hashes_by_type


def post_json(url: str, doc: dict, *, token: str | None, timeout: float = 30):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        url, data=canonical_bytes(doc), headers=headers, method="POST"
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, json.loads(response.read()), (
                time.perf_counter() - started
            ) * 1000
    except urllib.error.HTTPError as ex:
        body = ex.read()
        return ex.code, json.loads(body) if body else {}, (
            time.perf_counter() - started
        ) * 1000


def get_json(url: str, timeout: float = 10):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read())


def witness_snapshot(challenge_nonce: str, label: str, expected_slots: set[str]) -> dict:
    status, doc, _ = post_json(
        WITNESS_ENDPOINT + "/snapshot",
        {"challenge_nonce": challenge_nonce, "snapshot_label": label},
        token=WITNESS_TOKEN,
        timeout=10,
    )
    if status != 200:
        raise RuntimeError(f"witness HTTP {status}: {doc}")
    slots = doc["snapshot"]["slots"]
    if set(slots) != expected_slots:
        raise RuntimeError(
            f"witness slot mismatch {sorted(slots)} != {sorted(expected_slots)}"
        )
    for slot, row in slots.items():
        if not row.get("process_alive") or not row.get("direct_sbi_tcp_reachable"):
            raise RuntimeError(f"witness slot not live: {slot} {row}")
    return doc


def clean_runtime_files():
    PLAN_ROOT.mkdir(parents=True, exist_ok=True)
    WITNESS_DIR.mkdir(parents=True, exist_ok=True)
    (PLAN_ROOT / "enabled").unlink(missing_ok=True)
    (PLAN_ROOT / "plan.tsv").unlink(missing_ok=True)
    for path in WITNESS_DIR.glob("*.tsv"):
        path.unlink(missing_ok=True)


def start_process(name: str, binary: str, config: str) -> subprocess.Popen:
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    handle = open(LOG_ROOT / f"stage38-{name}-stdout.log", "ab", buffering=0)
    proc = subprocess.Popen(
        [binary, "-c", str(CONFIG_ROOT / config)],
        stdout=handle, stderr=subprocess.STDOUT, start_new_session=True,
        env={**os.environ, "STAGE38_WITNESS_DIR": str(WITNESS_DIR)},
    )
    PROCESSES[name] = proc
    return proc


async def stop_process(name: str):
    proc = PROCESSES.get(name)
    if not proc:
        return
    if proc.poll() is None:
        proc.terminate()
    deadline = time.time() + 4
    while proc.poll() is None and time.time() < deadline:
        await asyncio.sleep(0.05)
    if proc.poll() is None:
        proc.kill()
        await asyncio.sleep(0.05)
    PROCESSES.pop(name, None)


async def stop_all_processes():
    for name in list(PROCESSES):
        await stop_process(name)


def start_slot(slot: str):
    row = SLOTS[slot]
    return start_process(slot, BINARIES[row["type"]], row["config"])


def process_diagnostics() -> dict:
    result = {}
    for name, proc in PROCESSES.items():
        row = {"poll": proc.poll()}
        log_path = LOG_ROOT / f"stage38-{name}-stdout.log"
        if log_path.exists():
            row["log_tail"] = log_path.read_text(errors="replace")[-2500:]
        result[name] = row
    return result


async def wait_counts(expected: dict[str, int], timeout: float = 12.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            projections, _ = await discover_all()
            got = {t: state_counts(projections[t]) for t in NF_TYPES}
            target = {t: (expected[t], expected[t]) for t in NF_TYPES}
            last = got
            if got == target:
                return projections
        except Exception as ex:
            last = f"{type(ex).__name__}: {ex}"
        await asyncio.sleep(0.1)
    raise RuntimeError(f"multi-NF convergence failed: {last}; diagnostics={process_diagnostics()}")


def active_counts(active_slots: set[str]) -> dict[str, int]:
    return {
        nf_type: sum(1 for slot in active_slots if SLOTS[slot]["type"] == nf_type)
        for nf_type in NF_TYPES
    }


async def capture_reference(active_slots: set[str]) -> dict:
    expected = active_counts(active_slots)
    projection = await wait_counts(expected)
    first = canonical_bytes(projection)
    for _ in range(2):
        check, _ = await discover_all()
        if canonical_bytes(check) != first:
            raise RuntimeError("clean multi-NF reference was not stable")
        await asyncio.sleep(0.02)
    return projection


async def restart_testbed(challenge_nonce: str) -> tuple[dict, dict]:
    await stop_all_processes()
    clean_runtime_files()
    for p in LOG_ROOT.glob("stage38-*.log"):
        p.unlink(missing_ok=True)
    for p in LOG_ROOT.glob("*.log"):
        if p.name in {"nrf.log", "scp.log"}:
            p.unlink(missing_ok=True)

    start_process("nrf", "/src/open5gs/build/src/nrf/open5gs-nrfd", "nrf.yaml")
    await asyncio.sleep(0.35)
    start_process("scp", "/src/open5gs/build/src/scp/open5gs-scpd", "scp.yaml")
    for slot in SLOTS:
        start_slot(slot)
        await asyncio.sleep(0.05)

    active = set(SLOTS)
    reference = await capture_reference(active)
    witness = witness_snapshot(challenge_nonce, "initial", active)
    return reference, witness


TOPOLOGY_TEMPLATES = (
    (("stop", "nssf1"), ("start", "nssf1"), ("restart", "ausf1")),
    (("restart", "bsf1"), ("stop", "ausf2"), ("start", "ausf2")),
    (("stop", "udm1"), ("restart", "nssf2"), ("start", "udm1")),
    (("restart", "ausf1"), ("stop", "bsf2"), ("start", "bsf2")),
    (("stop", "nssf2"), ("restart", "udm2"), ("start", "nssf2")),
    (("restart", "bsf2"), ("stop", "nssf1"), ("start", "nssf1")),
    (("stop", "ausf1"), ("restart", "udm1"), ("start", "ausf1")),
    (("restart", "nssf1"), ("stop", "udm2"), ("start", "udm2")),
)


def build_scenario(seed: int, challenge_nonce: str) -> dict:
    secret = secrets.token_hex(32)
    digest = hashlib.sha256(
        f"{seed}:{challenge_nonce}:{secret}".encode()
    ).digest()
    rng = random.Random(int.from_bytes(digest, "big"))

    pre_ticks = rng.randint(3, 5)
    post_ticks = rng.randint(3, 5)
    densities = ["low", "medium", "high"]
    rng.shuffle(densities)
    template_id = seed % len(TOPOLOGY_TEMPLATES)

    active = set(SLOTS)
    cursor = pre_ticks
    events = []
    attack_requests = []

    for index, (operation, slot) in enumerate(TOPOLOGY_TEMPLATES[template_id]):
        duration = rng.randint(6, 10)
        density_bin = densities[index]
        lo, hi = DENSITY_RANGES[density_bin]
        count = max(2, min(duration, round(duration * rng.uniform(lo, hi))))
        ticks = sorted(rng.sample(range(cursor, cursor + duration), count))

        if operation == "stop":
            active.remove(slot)
        elif operation == "start":
            active.add(slot)
        elif operation != "restart":
            raise RuntimeError("invalid topology template")

        stable = sorted(active - {slot})
        by_type = {}
        for candidate in stable:
            by_type.setdefault(SLOTS[candidate]["type"], []).append(candidate)

        for tick in ticks:
            first = rng.choice(stable)
            targets = [first]
            if rng.random() < 0.35:
                other = [
                    s for s in stable
                    if SLOTS[s]["type"] != SLOTS[first]["type"]
                ]
                if other:
                    targets.append(rng.choice(other))
            for target in targets:
                attack_requests.append({
                    "tick": tick,
                    "event_index": index,
                    "target_slot": target,
                    "target_nf_type": SLOTS[target]["type"],
                    "simultaneous_count": len(targets),
                })

        events.append({
            "index": index,
            "operation": operation,
            "slot": slot,
            "slot_nf_type": SLOTS[slot]["type"],
            "phase": f"transition_{index}",
            "pre_reference": "initial" if index == 0 else f"ref_{index-1}",
            "post_reference": f"ref_{index}",
            "start_tick": cursor,
            "end_tick": cursor + duration - 1,
            "duration_ticks": duration,
            "density_bin": density_bin,
            "attack_ticks": ticks,
        })
        cursor += duration

    family_pool = [
        KINDS[i % len(KINDS)] for i in range(len(attack_requests))
    ]
    rng.shuffle(family_pool)
    entries = []
    for req, kind in zip(attack_requests, family_pool):
        variant = rng.randint(1, 4)
        target = req["target_slot"]
        parameter = SLOTS[target]["code"] * 100 + variant
        entries.append({
            **req,
            "kind": kind,
            "variant": variant,
            "parameter": parameter,
        })

    plan_text = "".join(
        f"{row['target_nf_type']}\t{row['tick']}\t"
        f"{row['kind']}\t{row['parameter']}\n"
        for row in sorted(
            entries,
            key=lambda x: (x["target_nf_type"], x["tick"], x["target_slot"]),
        )
    )
    soak_start = cursor + post_ticks
    return {
        "template_id": template_id,
        "pre_ticks": pre_ticks,
        "post_ticks": post_ticks,
        "soak_start": soak_start,
        "total_ticks": soak_start + CLEAN_SOAK_TICKS,
        "events": events,
        "entries": entries,
        "plan_text": plan_text,
        "plan_sha256": hashlib.sha256(plan_text.encode()).hexdigest(),
        "schedule_secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
    }


def install_plan(scenario: dict):
    PLAN_ROOT.mkdir(parents=True, exist_ok=True)
    (PLAN_ROOT / "plan.tsv").write_text(scenario["plan_text"], encoding="utf8")
    os.chmod(PLAN_ROOT / "plan.tsv", 0o400)
    (PLAN_ROOT / "enabled").touch()


def enable_hook():
    (PLAN_ROOT / "enabled").touch()


def disable_hook():
    (PLAN_ROOT / "enabled").unlink(missing_ok=True)


async def collect_tick(tick: int, phase: str) -> dict:
    started = time.perf_counter()
    projections, raw_hashes = await discover_all()
    return {
        "tick": tick,
        "phase": phase,
        "projections": projections,
        "legacy_counts": {
            nf_type: list(state_counts(projections[nf_type]))
            for nf_type in NF_TYPES
        },
        "raw_response_sha256": raw_hashes,
        "collector_discovery_latency_ms": (
            time.perf_counter() - started
        ) * 1000,
    }


async def lifecycle_operation(operation: str, slot: str, active: set[str]):
    if operation == "stop":
        await stop_process(slot)
        active.remove(slot)
    elif operation == "start":
        start_slot(slot)
        active.add(slot)
    elif operation == "restart":
        await stop_process(slot)
        start_slot(slot)
    else:
        raise RuntimeError(f"unknown lifecycle operation {operation}")


async def execute_scenario(
    scenario: dict, challenge_nonce: str, initial_ref: dict, initial_witness: dict
):
    references = {"initial": initial_ref}
    witnesses = {"initial": initial_witness}
    observations = []
    active = set(SLOTS)
    install_plan(scenario)

    tick = 0
    for _ in range(scenario["pre_ticks"]):
        observations.append(await collect_tick(tick, "steady_pre"))
        tick += 1
        await asyncio.sleep(0.008)

    for event in scenario["events"]:
        await lifecycle_operation(event["operation"], event["slot"], active)
        enable_hook()
        for _ in range(event["duration_ticks"]):
            observations.append(await collect_tick(tick, event["phase"]))
            tick += 1
            await asyncio.sleep(0.010)

        disable_hook()
        ref_name = event["post_reference"]
        references[ref_name] = await capture_reference(active)
        witnesses[ref_name] = witness_snapshot(
            challenge_nonce, ref_name, set(active)
        )
        enable_hook()

    for _ in range(scenario["post_ticks"]):
        observations.append(await collect_tick(tick, "steady_post"))
        tick += 1
        await asyncio.sleep(0.008)

    disable_hook()
    for _ in range(CLEAN_SOAK_TICKS):
        observations.append(await collect_tick(tick, "clean_soak"))
        tick += 1
        await asyncio.sleep(0.003)

    if tick != scenario["total_ticks"]:
        raise RuntimeError(
            f"observation tick mismatch {tick} != {scenario['total_ticks']}"
        )
    return references, witnesses, observations


def sign_package(package: dict) -> str:
    sig = PRIVATE_KEY.sign(canonical_bytes(package), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()


async def run_experiment(seed: int, challenge_nonce: str) -> dict:
    initial_ref, initial_witness = await restart_testbed(challenge_nonce)
    scenario = build_scenario(seed, challenge_nonce)
    references, witnesses, observations = await execute_scenario(
        scenario, challenge_nonce, initial_ref, initial_witness
    )

    nrf_log = LOG_ROOT / "nrf.log"
    native_log = nrf_log.read_text(errors="replace") if nrf_log.exists() else ""
    marker_count = native_log.count("STAGE38_NATIVE_NRF_MULTI_NF_MUTATION")
    if marker_count != len(scenario["entries"]):
        raise RuntimeError(
            f"native mutation marker mismatch {marker_count} != "
            f"{len(scenario['entries'])}"
        )

    sequence = next_sequence()
    public_events = [
        {k: e[k] for k in (
            "index", "operation", "slot", "slot_nf_type", "phase",
            "pre_reference", "post_reference", "start_tick",
            "end_tick", "duration_ticks",
        )}
        for e in scenario["events"]
    ]
    package = {
        "stage": STAGE,
        "schema": "stage38-multi-nf-witness-telemetry-v1",
        "seed": seed,
        "challenge_nonce": challenge_nonce,
        "collector_sequence": sequence,
        "collector_service_revision": SERVICE_REVISION,
        "collector_public_key_sha256": PUBLIC_KEY_SHA256,
        "policy_sha256": POLICY_SHA256,
        "open5gs_ref": OPEN5GS_REF,
        "nf_types": list(NF_TYPES),
        "lifecycle_plan": {
            "template_id": scenario["template_id"],
            "pre_ticks": scenario["pre_ticks"],
            "post_ticks": scenario["post_ticks"],
            "soak_start": scenario["soak_start"],
            "events": public_events,
        },
        "reference_states": references,
        "witness_snapshots": witnesses,
        "observations": observations,
        "native_nrf_source_sha256": hashlib.sha256(
            Path("/opt/stage38/stage38-nnrf-handler.c").read_bytes()
        ).hexdigest(),
        "attack_labels_in_package": False,
    }
    collector_signature = sign_package(package)
    request = {
        "telemetry_package": package,
        "collector_signature_base64": collector_signature,
    }

    unauth_status, _, unauth_ms = post_json(
        VERIFIER_A + "/verify", request, token=None, timeout=20
    )
    if unauth_status != 401:
        raise RuntimeError(
            f"verifier accepted unauthenticated collector: {unauth_status}"
        )

    status, verifier_result, verifier_ms = post_json(
        VERIFIER_A + "/verify", request, token=VERIFIER_TOKEN, timeout=45
    )
    if status != 200:
        raise RuntimeError(f"verifier A failed HTTP {status}: {verifier_result}")

    replay_status, replay_doc, replay_ms = post_json(
        VERIFIER_B + "/verify", request, token=VERIFIER_TOKEN, timeout=45
    )
    if replay_status not in (409, 422):
        raise RuntimeError(
            f"cross-verifier replay accepted: {replay_status} {replay_doc}"
        )

    labels = {
        "stage": STAGE,
        "seed": seed,
        "challenge_nonce": challenge_nonce,
        "topology_template_id": scenario["template_id"],
        "lifecycle_events": scenario["events"],
        "attack_entries": scenario["entries"],
        "attack_families": list(KINDS),
        "private_plan_sha256": scenario["plan_sha256"],
        "schedule_secret_sha256": scenario["schedule_secret_sha256"],
        "clean_soak_ticks": CLEAN_SOAK_TICKS,
        "labels_join_posthoc_only": True,
    }
    latencies = [
        float(row["collector_discovery_latency_ms"]) for row in observations
    ]
    evidence = {
        "stage": STAGE,
        "seed": seed,
        "topology_template_id": scenario["template_id"],
        "attack_entry_count": len(scenario["entries"]),
        "compound_attack_entries": sum(
            1 for e in scenario["entries"] if e["simultaneous_count"] > 1
        ),
        "total_observation_ticks": len(observations),
        "native_mutation_marker_count": marker_count,
        "collector_public_key_sha256": PUBLIC_KEY_SHA256,
        "witness_public_key_sha256": initial_witness["snapshot"][
            "witness_public_key_sha256"
        ],
        "verifier_latency_ms": verifier_ms,
        "unauthenticated_control_latency_ms": unauth_ms,
        "cross_instance_replay_status": replay_status,
        "cross_instance_replay_latency_ms": replay_ms,
        "collector_discovery_latency_ms": {
            "mean": sum(latencies) / len(latencies),
            "max": max(latencies),
        },
        "multi_nf_scope": {
            "nf_types": list(NF_TYPES),
            "instances": len(SLOTS),
            "independent_witness_channel": True,
            "witness_uses_nrf_discovery": False,
        },
    }
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
        "evidence": evidence,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Stage38MultiNFCollector/1.0"

    def send_json(self, status: int, doc: dict):
        body = json.dumps(doc, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            witness = get_json(WITNESS_ENDPOINT + "/health")
            self.send_json(200, {
                "stage": STAGE,
                "status": "ok",
                "policy_sha256": POLICY_SHA256,
                "collector_public_key_sha256": PUBLIC_KEY_SHA256,
                "witness_public_key_sha256": witness[
                    "witness_public_key_sha256"
                ],
                "nf_types": list(NF_TYPES),
                "nf_instance_slots": len(SLOTS),
                "witness_uses_nrf_discovery": False,
                "service_revision": SERVICE_REVISION,
            })
            return
        if self.path == "/public-key":
            self.send_json(200, {
                "stage": STAGE,
                "public_key_pem": PUBLIC_KEY_PEM.decode(),
                "public_key_sha256": PUBLIC_KEY_SHA256,
            })
            return
        if self.path == "/witness-public-key":
            self.send_json(200, get_json(WITNESS_ENDPOINT + "/public-key"))
            return
        self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/run":
            self.send_json(404, {"error": "not found"})
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
                self.send_json(429, {"error": "collector busy"})
                return
            try:
                result = asyncio.run(run_experiment(seed, nonce))
            finally:
                RUN_LOCK.release()
            self.send_json(200, result)
        except PermissionError as ex:
            self.send_json(403, {"error": str(ex)})
        except Exception as ex:
            print(
                "STAGE38_COLLECTOR_ERROR "
                f"{type(ex).__name__}: {ex}", flush=True
            )
            self.send_json(422, {"error": f"{type(ex).__name__}: {ex}"})

    def log_message(self, fmt, *args):
        print("STAGE38_COLLECTOR_HTTP", fmt % args, flush=True)


def start_witness():
    global WITNESS_PROCESS
    WITNESS_DIR.mkdir(parents=True, exist_ok=True)
    handle = open(LOG_ROOT / "stage38-witness-stdout.log", "ab", buffering=0)
    WITNESS_PROCESS = subprocess.Popen(
        ["python3", str(CONFIG_ROOT / "deployment_witness.py")],
        stdout=handle, stderr=subprocess.STDOUT, start_new_session=True,
        env=os.environ.copy(),
    )
    for _ in range(100):
        try:
            if get_json(WITNESS_ENDPOINT + "/health").get("status") == "ok":
                return
        except Exception:
            pass
        time.sleep(0.05)
    raise RuntimeError("deployment witness failed readiness")


def main():
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    start_witness()
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(
        "STAGE38_MULTI_NF_COLLECTOR_READY "
        f"port={port} policy={POLICY_SHA256} key={PUBLIC_KEY_SHA256} "
        f"nf_types={','.join(NF_TYPES)} slots={len(SLOTS)}",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        try:
            asyncio.run(stop_all_processes())
        except Exception:
            pass
        if WITNESS_PROCESS and WITNESS_PROCESS.poll() is None:
            WITNESS_PROCESS.terminate()


if __name__ == "__main__":
    main()
