"""Stage 37 randomized-topology transition-aware relational verifier."""
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

STAGE = 37
MAX_BODY = 8_000_000

POLICY_SHA256 = os.environ["STAGE37_POLICY_SHA256"].lower()
SERVICE_REVISION = os.environ.get("STAGE37_VERIFIER_REVISION", "unrecorded")
INSTANCE_NAME = os.environ.get("STAGE37_VERIFIER_INSTANCE", "unknown")
COLLECTOR_TOKEN = os.environ["STAGE37_COLLECTOR_TO_VERIFIER_TOKEN"]
ANCHOR_TOKEN = os.environ["STAGE37_ANCHOR_TOKEN"]
ANCHOR_ENDPOINT = os.environ["STAGE37_ANCHOR_ENDPOINT"].rstrip("/")

collector_public_pem = os.environ["STAGE37_COLLECTOR_PUBLIC_KEY_PEM"].encode("utf8")
COLLECTOR_PUBLIC_KEY = serialization.load_pem_public_key(collector_public_pem)
if not isinstance(COLLECTOR_PUBLIC_KEY, ec.EllipticCurvePublicKey):
    raise RuntimeError("collector public key must be EC")
COLLECTOR_PUBLIC_KEY_SHA256 = hashlib.sha256(collector_public_pem).hexdigest()
if COLLECTOR_PUBLIC_KEY_SHA256 != os.environ[
    "STAGE37_COLLECTOR_PUBLIC_KEY_SHA256"
].lower():
    raise RuntimeError("collector public-key fingerprint mismatch")

_private_pem = os.environ.get("STAGE37_VERIFIER_PRIVATE_KEY_PEM")
if not _private_pem:
    raise RuntimeError("STAGE37_VERIFIER_PRIVATE_KEY_PEM is required")
PRIVATE_KEY = serialization.load_pem_private_key(
    _private_pem.encode("utf8"), password=None
)
if not isinstance(PRIVATE_KEY, ec.EllipticCurvePrivateKey):
    raise RuntimeError("verifier private key must be EC")
KEY_ORIGIN = "render_environment"
PUBLIC_KEY_PEM = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY_PEM).hexdigest()

SLOT_ENDPOINTS = {
    "nssf1": "127.0.0.12",
    "nssf2": "127.0.0.13",
}


def canonical_bytes(doc) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def authorized(header: str | None) -> bool:
    prefix = "Bearer "
    if not header or not header.startswith(prefix):
        return False
    return hmac.compare_digest(header[len(prefix):], COLLECTOR_TOKEN)


def post_json(url: str, doc: dict, token: str, timeout: float = 10):
    request = urllib.request.Request(
        url,
        data=canonical_bytes(doc),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as ex:
        body = ex.read()
        return ex.code, json.loads(body) if body else {}


def verify_collector_signature(package: dict, signature_b64: str) -> None:
    COLLECTOR_PUBLIC_KEY.verify(
        base64.b64decode(signature_b64, validate=True),
        canonical_bytes(package),
        ec.ECDSA(hashes.SHA256()),
    )


def projection_equal(left: dict, right: dict) -> bool:
    return canonical_bytes(left) == canonical_bytes(right)


def state_counts(projection: dict) -> tuple[int, int]:
    profiles = projection.get("profiles", {})
    count = len(profiles)
    registered = sum(
        1 for row in profiles.values()
        if row.get("nfStatus") == "REGISTERED"
    )
    return count, registered


def slot_profile(projection: dict, slot: str):
    endpoint = SLOT_ENDPOINTS[slot]
    matches = []
    for nf_id, attrs in projection.get("profiles", {}).items():
        if endpoint in (attrs.get("ipv4Addresses") or []):
            matches.append((nf_id, attrs))
    if len(matches) != 1:
        return None
    return matches[0]


def only_known_slots(projection: dict) -> bool:
    assigned = set()
    for slot in SLOT_ENDPOINTS:
        item = slot_profile(projection, slot)
        if item is not None:
            assigned.add(item[0])
    return assigned == set(projection.get("profiles", {}))


def same_slot(
    observed: dict,
    reference: dict,
    slot: str,
    *,
    allow_identity_change: bool,
) -> bool:
    left = slot_profile(observed, slot)
    right = slot_profile(reference, slot)
    if left is None or right is None:
        return False
    left_id, left_attrs = left
    right_id, right_attrs = right
    if not allow_identity_change and left_id != right_id:
        return False
    return canonical_bytes(left_attrs) == canonical_bytes(right_attrs)


def other_slot(slot: str) -> str:
    return "nssf2" if slot == "nssf1" else "nssf1"


def validate_lifecycle(plan: dict, refs: dict, observations: list[dict]) -> dict[str, dict]:
    if not isinstance(plan, dict):
        raise ValueError("missing lifecycle plan")
    events = plan.get("events")
    if not isinstance(events, list) or len(events) != 3:
        raise ValueError("expected exactly three lifecycle events")
    pre_ticks = int(plan.get("pre_ticks", -1))
    post_ticks = int(plan.get("post_ticks", -1))
    if not 3 <= pre_ticks <= 6 or not 3 <= post_ticks <= 6:
        raise ValueError("invalid steady control length")

    active = {"nssf1", "nssf2"}
    cursor = pre_ticks
    by_phase = {}
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError("invalid lifecycle event")
        phase = str(event.get("phase"))
        if phase != f"transition_{index}":
            raise ValueError("lifecycle phase/index mismatch")
        operation = str(event.get("operation"))
        slot = str(event.get("slot"))
        stable_slot = str(event.get("stable_slot"))
        if slot not in SLOT_ENDPOINTS or stable_slot != other_slot(slot):
            raise ValueError("invalid lifecycle slot")
        if operation not in ("stop", "start", "restart"):
            raise ValueError("invalid lifecycle operation")
        if operation == "stop":
            if slot not in active:
                raise ValueError("cannot stop absent slot")
            active.remove(slot)
        elif operation == "start":
            if slot in active:
                raise ValueError("cannot start active slot")
            active.add(slot)
        elif slot not in active:
            raise ValueError("cannot restart absent slot")

        pre_ref = str(event.get("pre_reference"))
        post_ref = str(event.get("post_reference"))
        expected_pre = "initial" if index == 0 else f"ref_{index-1}"
        expected_post = f"ref_{index}"
        if pre_ref != expected_pre or post_ref != expected_post:
            raise ValueError("reference chain mismatch")
        if not isinstance(refs.get(pre_ref), dict) or not isinstance(refs.get(post_ref), dict):
            raise ValueError("missing lifecycle reference")

        start = int(event.get("start_tick", -1))
        end = int(event.get("end_tick", -1))
        duration = int(event.get("duration_ticks", -1))
        if start != cursor or duration < 8 or duration > 14 or end != start + duration - 1:
            raise ValueError("invalid transition span")
        cursor = end + 1
        by_phase[phase] = event

    if active != {"nssf1", "nssf2"}:
        raise ValueError("lifecycle does not restore two active slots")
    if int(plan.get("steady_post_start", -1)) != cursor:
        raise ValueError("steady post start mismatch")
    soak_start = cursor + post_ticks
    if int(plan.get("soak_start", -1)) != soak_start:
        raise ValueError("soak start mismatch")
    if len(observations) < soak_start:
        raise ValueError("observation stream too short")
    return by_phase


def transition_relational_alert(
    projection: dict,
    refs: dict,
    event: dict,
) -> bool:
    if not only_known_slots(projection):
        return True

    stable_slot = event["stable_slot"]
    moving_slot = event["slot"]
    pre_ref = refs[event["pre_reference"]]
    post_ref = refs[event["post_reference"]]

    # The stable slot is never allowed to change identity or relations.
    if not same_slot(
        projection, pre_ref, stable_slot, allow_identity_change=False
    ):
        return True

    # The moving slot may legitimately disappear. If present, its relational
    # attributes must match either the authorized pre- or post-transition state.
    moving = slot_profile(projection, moving_slot)
    if moving is None:
        return False
    if same_slot(
        projection, pre_ref, moving_slot, allow_identity_change=True
    ):
        return False
    if same_slot(
        projection, post_ref, moving_slot, allow_identity_change=True
    ):
        return False
    return True


def verify_package(package: dict, collector_signature: str) -> dict:
    started = time.perf_counter()

    if int(package.get("stage", -1)) != STAGE:
        raise ValueError("stage mismatch")
    if package.get("schema") != "stage37-randomized-transition-telemetry-v1":
        raise ValueError("schema mismatch")
    if package.get("policy_sha256") != POLICY_SHA256:
        raise PermissionError("policy mismatch")
    if package.get("collector_public_key_sha256") != COLLECTOR_PUBLIC_KEY_SHA256:
        raise ValueError("collector key mismatch")
    if package.get("attack_labels_in_package") is not False:
        raise ValueError("private attack labels are forbidden")

    verify_collector_signature(package, collector_signature)

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
    observations = package.get("observations")
    plan = package.get("lifecycle_plan")
    if not isinstance(refs, dict) or not isinstance(observations, list):
        raise ValueError("missing references/observations")
    for name in ("initial", "ref_0", "ref_1", "ref_2"):
        if not isinstance(refs.get(name), dict):
            raise ValueError(f"missing reference state {name}")
    by_phase = validate_lifecycle(plan, refs, observations)

    final_ref = refs["ref_2"]
    pre_ticks = int(plan["pre_ticks"])
    post_start = int(plan["steady_post_start"])
    soak_start = int(plan["soak_start"])

    alerts = []
    relational_alert_rows = 0
    legacy_alert_rows = 0

    for expected_tick, row in enumerate(observations):
        tick = int(row["tick"])
        if tick != expected_tick:
            raise ValueError("non-contiguous tick stream")
        phase = str(row["phase"])
        projection = row["projection"]

        if tick < pre_ticks:
            if phase != "steady_pre":
                raise ValueError("steady-pre phase mismatch")
            relational_alert = not projection_equal(projection, refs["initial"])
            allowed_names = ["initial"]
        elif phase in by_phase:
            event = by_phase[phase]
            if not int(event["start_tick"]) <= tick <= int(event["end_tick"]):
                raise ValueError("transition phase outside declared span")
            relational_alert = transition_relational_alert(
                projection, refs, event
            )
            allowed_names = [
                event["pre_reference"], event["post_reference"]
            ]
        elif post_start <= tick < soak_start:
            if phase != "steady_post":
                raise ValueError("steady-post phase mismatch")
            relational_alert = not projection_equal(projection, final_ref)
            allowed_names = ["ref_2"]
        else:
            if tick < soak_start or phase != "clean_soak":
                raise ValueError("clean-soak phase mismatch")
            relational_alert = not projection_equal(projection, final_ref)
            allowed_names = ["ref_2"]

        observed_counts = state_counts(projection)
        allowed_counts = {state_counts(refs[name]) for name in allowed_names}
        legacy_alert = observed_counts not in allowed_counts

        relational_alert_rows += int(relational_alert)
        legacy_alert_rows += int(legacy_alert)
        alerts.append(
            {
                "tick": tick,
                "phase": phase,
                "relational_alert": relational_alert,
                "legacy_count_status_alert": legacy_alert,
                "allowed_references": list(allowed_names),
                "observed_counts": list(observed_counts),
            }
        )

    core = {
        "stage": STAGE,
        "schema": "stage37-randomized-transition-verdict-v1",
        "seed": int(package["seed"]),
        "challenge_nonce": nonce,
        "collector_sequence": sequence,
        "collector_package_sha256": package_sha,
        "policy_sha256": POLICY_SHA256,
        "collector_public_key_sha256": COLLECTOR_PUBLIC_KEY_SHA256,
        "verifier_public_key_sha256": PUBLIC_KEY_SHA256,
        "verifier_service_revision": SERVICE_REVISION,
        "verifier_instance": INSTANCE_NAME,
        "freshness_anchor_service_revision": anchor_result["service_revision"],
        "freshness_anchor_last_sequence": anchor_result["last_sequence"],
        "telemetry_rows": len(observations),
        "relational_alert_rows": relational_alert_rows,
        "legacy_count_status_alert_rows": legacy_alert_rows,
        "alerts": alerts,
        "attack_labels_received": False,
        "client_authentication": "bearer_collector_to_verifier",
        "freshness_state": "external_anchor_process",
        "anchor_latency_ms": anchor_ms,
        "processing_ms": (time.perf_counter() - started) * 1000,
    }
    signature = PRIVATE_KEY.sign(
        canonical_bytes(core), ec.ECDSA(hashes.SHA256())
    )
    return {
        "verdict": core,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Stage37RandomizedRelationalVerifier/1.0"

    def send_json(self, status: int, doc: dict) -> None:
        body = json.dumps(doc, sort_keys=True).encode("utf8")
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
                "verifier_public_key_sha256": PUBLIC_KEY_SHA256,
                "service_revision": SERVICE_REVISION,
                "verifier_instance": INSTANCE_NAME,
                "freshness_anchor_endpoint": ANCHOR_ENDPOINT,
                "client_authentication_required": True,
                "verifier_key_origin": KEY_ORIGIN,
            })
            return
        if self.path == "/public-key":
            self.send_json(200, {
                "stage": STAGE,
                "public_key_pem": PUBLIC_KEY_PEM.decode("ascii"),
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
            request = json.loads(self.rfile.read(length))
            result = verify_package(
                request["telemetry_package"],
                request["collector_signature_base64"],
            )
            self.send_json(200, result)
        except PermissionError as ex:
            self.send_json(403, {"error": str(ex)})
        except Exception as ex:
            self.send_json(422, {"error": f"{type(ex).__name__}: {ex}"})

    def log_message(self, fmt, *args):
        print(f"STAGE37_VERIFIER_{INSTANCE_NAME}_HTTP", fmt % args, flush=True)


def main():
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(
        "STAGE37_RANDOMIZED_VERIFIER_READY "
        f"instance={INSTANCE_NAME} port={port} policy={POLICY_SHA256} "
        f"collector_key={COLLECTOR_PUBLIC_KEY_SHA256} "
        f"verifier_key={PUBLIC_KEY_SHA256}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
