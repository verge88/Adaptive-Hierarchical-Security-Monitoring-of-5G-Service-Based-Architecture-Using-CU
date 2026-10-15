"""Stage 38 multi-NF relational verifier with signed NF-side witness."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

STAGE = 38
MAX_BODY = 20_000_000
NF_TYPES = ("NSSF", "AUSF", "BSF", "UDM")
SLOTS = {
    "nssf1": {"type": "NSSF", "endpoint": "127.0.0.12"},
    "nssf2": {"type": "NSSF", "endpoint": "127.0.0.13"},
    "ausf1": {"type": "AUSF", "endpoint": "127.0.0.14"},
    "ausf2": {"type": "AUSF", "endpoint": "127.0.0.15"},
    "bsf1": {"type": "BSF", "endpoint": "127.0.0.16"},
    "bsf2": {"type": "BSF", "endpoint": "127.0.0.17"},
    "udm1": {"type": "UDM", "endpoint": "127.0.0.18"},
    "udm2": {"type": "UDM", "endpoint": "127.0.0.19"},
}

POLICY_SHA256 = os.environ["STAGE38_POLICY_SHA256"].lower()
SERVICE_REVISION = os.environ.get("STAGE38_VERIFIER_REVISION", "unrecorded")
INSTANCE_NAME = os.environ.get("STAGE38_VERIFIER_INSTANCE", "unknown")
COLLECTOR_TOKEN = os.environ["STAGE38_COLLECTOR_TO_VERIFIER_TOKEN"]
ANCHOR_TOKEN = os.environ["STAGE38_ANCHOR_TOKEN"]
ANCHOR_ENDPOINT = os.environ["STAGE38_ANCHOR_ENDPOINT"].rstrip("/")

collector_pem = os.environ["STAGE38_COLLECTOR_PUBLIC_KEY_PEM"].encode()
COLLECTOR_PUBLIC_KEY = serialization.load_pem_public_key(collector_pem)
if not isinstance(COLLECTOR_PUBLIC_KEY, ec.EllipticCurvePublicKey):
    raise RuntimeError("collector key must be EC")
COLLECTOR_PUBLIC_KEY_SHA256 = hashlib.sha256(collector_pem).hexdigest()
if COLLECTOR_PUBLIC_KEY_SHA256 != os.environ[
    "STAGE38_COLLECTOR_PUBLIC_KEY_SHA256"
].lower():
    raise RuntimeError("collector key fingerprint mismatch")

witness_pem = os.environ["STAGE38_WITNESS_PUBLIC_KEY_PEM"].encode()
WITNESS_PUBLIC_KEY = serialization.load_pem_public_key(witness_pem)
if not isinstance(WITNESS_PUBLIC_KEY, ec.EllipticCurvePublicKey):
    raise RuntimeError("witness key must be EC")
WITNESS_PUBLIC_KEY_SHA256 = hashlib.sha256(witness_pem).hexdigest()
if WITNESS_PUBLIC_KEY_SHA256 != os.environ[
    "STAGE38_WITNESS_PUBLIC_KEY_SHA256"
].lower():
    raise RuntimeError("witness key fingerprint mismatch")

private_pem = os.environ["STAGE38_VERIFIER_PRIVATE_KEY_PEM"].encode()
PRIVATE_KEY = serialization.load_pem_private_key(private_pem, password=None)
if not isinstance(PRIVATE_KEY, ec.EllipticCurvePrivateKey):
    raise RuntimeError("verifier key must be EC")
PUBLIC_KEY_PEM = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY_PEM).hexdigest()


def canonical_bytes(doc) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def authorized(header: str | None) -> bool:
    if not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[7:], COLLECTOR_TOKEN)


def post_json(url: str, doc: dict, token: str, timeout: float = 10):
    req = urllib.request.Request(
        url,
        data=canonical_bytes(doc),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as ex:
        body = ex.read()
        return ex.code, json.loads(body) if body else {}


def verify_signature(key, doc: dict, signature_b64: str):
    key.verify(
        base64.b64decode(signature_b64, validate=True),
        canonical_bytes(doc),
        ec.ECDSA(hashes.SHA256()),
    )


def projection_equal(left: dict, right: dict) -> bool:
    return canonical_bytes(left) == canonical_bytes(right)


def state_counts(projection: dict) -> tuple[int, int]:
    profiles = projection.get("profiles", {})
    return (
        len(profiles),
        sum(1 for row in profiles.values() if row.get("nfStatus") == "REGISTERED"),
    )


def slot_profile(projection: dict, slot: str):
    endpoint = SLOTS[slot]["endpoint"]
    matches = []
    for nf_id, attrs in projection.get("profiles", {}).items():
        if endpoint in (attrs.get("ipv4Addresses") or []):
            matches.append((nf_id, attrs))
    if len(matches) != 1:
        return None
    return matches[0]


def slots_of_type(nf_type: str) -> list[str]:
    return [s for s, row in SLOTS.items() if row["type"] == nf_type]


def profile_count_across_refs(refs: dict) -> int:
    return sum(
        len(refs[t].get("profiles", {}))
        for t in NF_TYPES
    )


def reference_witness_consistent(
    ref: dict, witness_bundle: dict, label: str, nonce: str
):
    if not isinstance(witness_bundle, dict):
        raise ValueError(f"missing witness bundle {label}")
    snap = witness_bundle.get("snapshot")
    sig = witness_bundle.get("signature_base64")
    if not isinstance(snap, dict) or not isinstance(sig, str):
        raise ValueError("invalid witness bundle")
    verify_signature(WITNESS_PUBLIC_KEY, snap, sig)
    if int(snap.get("stage", -1)) != STAGE:
        raise ValueError("witness stage mismatch")
    if snap.get("policy_sha256") != POLICY_SHA256:
        raise PermissionError("witness policy mismatch")
    if snap.get("challenge_nonce") != nonce:
        raise ValueError("witness nonce mismatch")
    if snap.get("snapshot_label") != label:
        raise ValueError("witness label mismatch")
    if snap.get("nrf_discovery_used") is not False:
        raise ValueError("witness must be independent of NRF discovery")
    if snap.get("witness_public_key_sha256") != WITNESS_PUBLIC_KEY_SHA256:
        raise ValueError("witness key mismatch")

    slots = snap.get("slots")
    if not isinstance(slots, dict):
        raise ValueError("witness slots missing")

    for slot, row in slots.items():
        if slot not in SLOTS:
            raise ValueError(f"unknown witness slot {slot}")
        expected = SLOTS[slot]
        if row.get("nf_type") != expected["type"]:
            raise ValueError("witness type mismatch")
        if row.get("endpoint") != expected["endpoint"]:
            raise ValueError("witness endpoint mismatch")
        if row.get("process_alive") is not True:
            raise ValueError("witness process not alive")
        if row.get("direct_sbi_tcp_reachable") is not True:
            raise ValueError("witness SBI not reachable")
        projection = ref[expected["type"]]
        item = slot_profile(projection, slot)
        if item is None:
            raise ValueError(f"NRF reference lacks witnessed slot {slot}")
        nf_id, attrs = item
        if nf_id != str(row.get("nf_instance_id", "")).lower():
            raise ValueError(f"NRF/witness UUID mismatch for {slot}")
        if attrs.get("nfType") != expected["type"]:
            raise ValueError(f"NRF/witness type mismatch for {slot}")

    if profile_count_across_refs(ref) != len(slots):
        raise ValueError("NRF reference has unwitnessed profiles")
    return slots


def type_transition_alert(
    nf_type: str,
    observed: dict,
    pre: dict,
    post: dict,
    moving_slot: str,
) -> bool:
    moving_type = SLOTS[moving_slot]["type"]
    if nf_type != moving_type:
        return not projection_equal(observed, pre)

    authorized_slots = set(slots_of_type(nf_type))
    observed_assigned = set()
    for slot in authorized_slots:
        item = slot_profile(observed, slot)
        if item is not None:
            observed_assigned.add(item[0])
    if observed_assigned != set(observed.get("profiles", {})):
        return True

    for slot in authorized_slots - {moving_slot}:
        if slot_profile(observed, slot) != slot_profile(pre, slot):
            return True

    moving = slot_profile(observed, moving_slot)
    if moving is None:
        return False
    return not (
        moving == slot_profile(pre, moving_slot)
        or moving == slot_profile(post, moving_slot)
    )


def validate_lifecycle(plan: dict, refs: dict, witnesses: dict, nonce: str):
    if not isinstance(plan, dict):
        raise ValueError("missing lifecycle plan")
    events = plan.get("events")
    if not isinstance(events, list) or len(events) != 3:
        raise ValueError("expected three lifecycle events")
    pre_ticks = int(plan.get("pre_ticks", -1))
    post_ticks = int(plan.get("post_ticks", -1))
    if not 3 <= pre_ticks <= 5 or not 3 <= post_ticks <= 5:
        raise ValueError("invalid steady lengths")

    active = set(SLOTS)
    witness_slots = {}
    for label in ("initial", "ref_0", "ref_1", "ref_2"):
        ref = refs.get(label)
        if not isinstance(ref, dict) or set(ref) != set(NF_TYPES):
            raise ValueError(f"missing reference {label}")
        witness_slots[label] = reference_witness_consistent(
            ref, witnesses.get(label), label, nonce
        )

    if set(witness_slots["initial"]) != active:
        raise ValueError("initial witness does not contain all NF slots")

    cursor = pre_ticks
    by_phase = {}
    for i, event in enumerate(events):
        if event.get("phase") != f"transition_{i}":
            raise ValueError("phase/index mismatch")
        operation = str(event.get("operation"))
        slot = str(event.get("slot"))
        if slot not in SLOTS or operation not in ("stop", "start", "restart"):
            raise ValueError("invalid lifecycle event")
        if event.get("slot_nf_type") != SLOTS[slot]["type"]:
            raise ValueError("lifecycle NF type mismatch")
        pre_ref = "initial" if i == 0 else f"ref_{i-1}"
        post_ref = f"ref_{i}"
        if event.get("pre_reference") != pre_ref or event.get("post_reference") != post_ref:
            raise ValueError("reference chain mismatch")
        start = int(event.get("start_tick", -1))
        duration = int(event.get("duration_ticks", -1))
        end = int(event.get("end_tick", -1))
        if start != cursor or not 6 <= duration <= 10 or end != start + duration - 1:
            raise ValueError("invalid transition span")

        if operation == "stop":
            if slot not in active:
                raise ValueError("stopping absent slot")
            active.remove(slot)
        elif operation == "start":
            if slot in active:
                raise ValueError("starting active slot")
            active.add(slot)
        elif slot not in active:
            raise ValueError("restarting absent slot")

        if set(witness_slots[post_ref]) != active:
            raise ValueError(f"witness lifecycle mismatch after {operation} {slot}")
        by_phase[event["phase"]] = event
        cursor = end + 1

    if active != set(SLOTS):
        raise ValueError("lifecycle does not restore all NF slots")
    if int(plan.get("soak_start", -1)) != cursor + post_ticks:
        raise ValueError("soak boundary mismatch")
    return by_phase


def verify_package(package: dict, collector_signature: str) -> dict:
    started = time.perf_counter()
    if int(package.get("stage", -1)) != STAGE:
        raise ValueError("stage mismatch")
    if package.get("schema") != "stage38-multi-nf-witness-telemetry-v1":
        raise ValueError("schema mismatch")
    if package.get("policy_sha256") != POLICY_SHA256:
        raise PermissionError("policy mismatch")
    if package.get("collector_public_key_sha256") != COLLECTOR_PUBLIC_KEY_SHA256:
        raise ValueError("collector key mismatch")
    if package.get("attack_labels_in_package") is not False:
        raise ValueError("private attack labels forbidden")
    if tuple(package.get("nf_types", [])) != NF_TYPES:
        raise ValueError("NF scope mismatch")

    verify_signature(COLLECTOR_PUBLIC_KEY, package, collector_signature)
    package_sha = hashlib.sha256(canonical_bytes(package)).hexdigest()
    nonce = str(package["challenge_nonce"])
    sequence = int(package["collector_sequence"])

    anchor_started = time.perf_counter()
    anchor_status, anchor_result = post_json(
        ANCHOR_ENDPOINT + "/claim",
        {
            "stage": STAGE,
            "policy_sha256": POLICY_SHA256,
            "challenge_nonce": nonce,
            "collector_sequence": sequence,
            "collector_package_sha256": package_sha,
        },
        ANCHOR_TOKEN,
    )
    anchor_ms = (time.perf_counter() - anchor_started) * 1000
    if anchor_status != 200:
        raise ValueError(
            f"freshness anchor rejected package HTTP {anchor_status}: "
            f"{anchor_result}"
        )

    refs = package.get("reference_states")
    witnesses = package.get("witness_snapshots")
    observations = package.get("observations")
    if not isinstance(refs, dict) or not isinstance(witnesses, dict) or not isinstance(observations, list):
        raise ValueError("missing references/witnesses/observations")
    by_phase = validate_lifecycle(
        package.get("lifecycle_plan"), refs, witnesses, nonce
    )

    plan = package["lifecycle_plan"]
    pre_ticks = int(plan["pre_ticks"])
    soak_start = int(plan["soak_start"])
    post_start = int(by_phase["transition_2"]["end_tick"]) + 1
    final_ref = refs["ref_2"]

    alerts = []
    rel_rows = 0
    legacy_rows = 0
    for expected_tick, row in enumerate(observations):
        tick = int(row["tick"])
        if tick != expected_tick:
            raise ValueError("non-contiguous ticks")
        projections = row.get("projections")
        if not isinstance(projections, dict) or set(projections) != set(NF_TYPES):
            raise ValueError("invalid multi-NF projection row")
        phase = str(row["phase"])
        rel_by_type = {}
        legacy_by_type = {}

        if tick < pre_ticks:
            if phase != "steady_pre":
                raise ValueError("steady pre mismatch")
            for t in NF_TYPES:
                rel_by_type[t] = not projection_equal(
                    projections[t], refs["initial"][t]
                )
                legacy_by_type[t] = state_counts(projections[t]) != state_counts(
                    refs["initial"][t]
                )
        elif phase in by_phase:
            event = by_phase[phase]
            if not int(event["start_tick"]) <= tick <= int(event["end_tick"]):
                raise ValueError("transition span mismatch")
            pre_ref = refs[event["pre_reference"]]
            post_ref = refs[event["post_reference"]]
            moving = event["slot"]
            moving_type = SLOTS[moving]["type"]
            for t in NF_TYPES:
                rel_by_type[t] = type_transition_alert(
                    t, projections[t], pre_ref[t], post_ref[t], moving
                )
                allowed_counts = {state_counts(pre_ref[t])}
                if t == moving_type:
                    allowed_counts.add(state_counts(post_ref[t]))
                legacy_by_type[t] = state_counts(projections[t]) not in allowed_counts
        elif post_start <= tick < soak_start:
            if phase != "steady_post":
                raise ValueError("steady post mismatch")
            for t in NF_TYPES:
                rel_by_type[t] = not projection_equal(
                    projections[t], final_ref[t]
                )
                legacy_by_type[t] = state_counts(projections[t]) != state_counts(
                    final_ref[t]
                )
        else:
            if tick < soak_start or phase != "clean_soak":
                raise ValueError("clean soak mismatch")
            for t in NF_TYPES:
                rel_by_type[t] = not projection_equal(
                    projections[t], final_ref[t]
                )
                legacy_by_type[t] = state_counts(projections[t]) != state_counts(
                    final_ref[t]
                )

        relational_alert = any(rel_by_type.values())
        legacy_alert = any(legacy_by_type.values())
        rel_rows += int(relational_alert)
        legacy_rows += int(legacy_alert)
        alerts.append({
            "tick": tick,
            "phase": phase,
            "relational_alert": relational_alert,
            "legacy_count_status_alert": legacy_alert,
            "relational_alert_by_nf_type": rel_by_type,
            "legacy_alert_by_nf_type": legacy_by_type,
        })

    core = {
        "stage": STAGE,
        "schema": "stage38-multi-nf-witness-verdict-v1",
        "seed": int(package["seed"]),
        "challenge_nonce": nonce,
        "collector_sequence": sequence,
        "collector_package_sha256": package_sha,
        "policy_sha256": POLICY_SHA256,
        "collector_public_key_sha256": COLLECTOR_PUBLIC_KEY_SHA256,
        "witness_public_key_sha256": WITNESS_PUBLIC_KEY_SHA256,
        "verifier_public_key_sha256": PUBLIC_KEY_SHA256,
        "verifier_service_revision": SERVICE_REVISION,
        "verifier_instance": INSTANCE_NAME,
        "freshness_anchor_service_revision": anchor_result["service_revision"],
        "freshness_anchor_last_sequence": anchor_result["last_sequence"],
        "telemetry_rows": len(observations),
        "relational_alert_rows": rel_rows,
        "legacy_count_status_alert_rows": legacy_rows,
        "alerts": alerts,
        "attack_labels_received": False,
        "witness_signatures_verified": True,
        "witness_reference_bindings_verified": True,
        "processing_ms": (time.perf_counter() - started) * 1000,
        "anchor_latency_ms": anchor_ms,
    }
    sig = PRIVATE_KEY.sign(canonical_bytes(core), ec.ECDSA(hashes.SHA256()))
    return {
        "verdict": core,
        "signature_base64": base64.b64encode(sig).decode(),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Stage38MultiNFVerifier/1.0"

    def send_json(self, status: int, doc: dict):
        body = json.dumps(doc, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {
                "stage": STAGE,
                "status": "ok",
                "policy_sha256": POLICY_SHA256,
                "collector_public_key_sha256": COLLECTOR_PUBLIC_KEY_SHA256,
                "witness_public_key_sha256": WITNESS_PUBLIC_KEY_SHA256,
                "verifier_public_key_sha256": PUBLIC_KEY_SHA256,
                "verifier_instance": INSTANCE_NAME,
                "service_revision": SERVICE_REVISION,
                "nf_types": list(NF_TYPES),
                "witness_required": True,
            })
            return
        if self.path == "/public-key":
            self.send_json(200, {
                "stage": STAGE,
                "public_key_pem": PUBLIC_KEY_PEM.decode(),
                "public_key_sha256": PUBLIC_KEY_SHA256,
            })
            return
        self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/verify":
            self.send_json(404, {"error": "not found"})
            return
        if not authorized(self.headers.get("Authorization")):
            self.send_json(401, {"error": "collector authentication failed"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("invalid body length")
            req = json.loads(self.rfile.read(length))
            result = verify_package(
                req["telemetry_package"],
                req["collector_signature_base64"],
            )
            self.send_json(200, result)
        except PermissionError as ex:
            self.send_json(403, {"error": str(ex)})
        except Exception as ex:
            self.send_json(422, {"error": f"{type(ex).__name__}: {ex}"})

    def log_message(self, fmt, *args):
        print(f"STAGE38_VERIFIER_{INSTANCE_NAME}_HTTP", fmt % args, flush=True)


def main():
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(
        "STAGE38_MULTI_NF_VERIFIER_READY "
        f"instance={INSTANCE_NAME} port={port} policy={POLICY_SHA256} "
        f"collector_key={COLLECTOR_PUBLIC_KEY_SHA256} "
        f"witness_key={WITNESS_PUBLIC_KEY_SHA256} "
        f"verifier_key={PUBLIC_KEY_SHA256}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
