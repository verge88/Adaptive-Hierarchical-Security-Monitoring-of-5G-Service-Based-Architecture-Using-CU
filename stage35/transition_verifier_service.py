"""Stage 35 transition-aware external relational verifier.

Two independent verifier processes can run this same code. Freshness is claimed
through the separate Stage-35 anchor, so replay rejection is shared across
verifier processes. Collector-to-verifier and verifier-to-anchor requests are
authenticated with distinct bearer tokens held only in the external services.
"""
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

STAGE = 35
MAX_BODY = 8_000_000

POLICY_SHA256 = os.environ["STAGE35_POLICY_SHA256"].lower()
SERVICE_REVISION = os.environ.get("STAGE35_VERIFIER_REVISION", "unrecorded")
INSTANCE_NAME = os.environ.get("STAGE35_VERIFIER_INSTANCE", "unknown")
COLLECTOR_TOKEN = os.environ["STAGE35_COLLECTOR_TO_VERIFIER_TOKEN"]
ANCHOR_TOKEN = os.environ["STAGE35_ANCHOR_TOKEN"]
ANCHOR_ENDPOINT = os.environ["STAGE35_ANCHOR_ENDPOINT"].rstrip("/")

collector_public_pem = os.environ["STAGE35_COLLECTOR_PUBLIC_KEY_PEM"].encode(
    "utf8"
)
COLLECTOR_PUBLIC_KEY = serialization.load_pem_public_key(collector_public_pem)
if not isinstance(COLLECTOR_PUBLIC_KEY, ec.EllipticCurvePublicKey):
    raise RuntimeError("collector public key must be EC")
COLLECTOR_PUBLIC_KEY_SHA256 = hashlib.sha256(
    collector_public_pem
).hexdigest()
if COLLECTOR_PUBLIC_KEY_SHA256 != os.environ[
    "STAGE35_COLLECTOR_PUBLIC_KEY_SHA256"
].lower():
    raise RuntimeError("collector public-key fingerprint mismatch")

_private_pem = os.environ.get("STAGE35_VERIFIER_PRIVATE_KEY_PEM")
if _private_pem:
    PRIVATE_KEY = serialization.load_pem_private_key(
        _private_pem.encode("utf8"), password=None
    )
    KEY_ORIGIN = "render_environment"
else:
    PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
    KEY_ORIGIN = "render_process_generated_ephemeral"
if not isinstance(PRIVATE_KEY, ec.EllipticCurvePrivateKey):
    raise RuntimeError("verifier private key must be EC")
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


PHASE_ALLOWED_REFERENCES = {
    "steady_pre": ("initial",),
    "stop_transition": ("initial", "after_stop"),
    "start_transition": ("after_stop", "after_start"),
    "restart_transition": ("after_start", "after_restart"),
    "steady_post": ("after_restart",),
    "clean_soak": ("after_restart",),
}


def state_counts(projection: dict) -> tuple[int, int]:
    profiles = projection.get("profiles", {})
    count = len(profiles)
    registered = sum(
        1
        for row in profiles.values()
        if row.get("nfStatus") == "REGISTERED"
    )
    return count, registered


def verify_package(package: dict, collector_signature: str) -> dict:
    started = time.perf_counter()

    if int(package.get("stage", -1)) != STAGE:
        raise ValueError("stage mismatch")
    if package.get("schema") != "stage35-transition-relational-telemetry-v1":
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
    if not isinstance(refs, dict) or not isinstance(observations, list):
        raise ValueError("missing references/observations")
    for name in ("initial", "after_stop", "after_start", "after_restart"):
        if not isinstance(refs.get(name), dict):
            raise ValueError(f"missing reference state {name}")

    alerts = []
    relational_alert_rows = 0
    legacy_alert_rows = 0
    phase_clean_false_alert_rows = 0

    for expected_tick, row in enumerate(observations):
        tick = int(row["tick"])
        if tick != expected_tick:
            raise ValueError("non-contiguous tick stream")
        phase = str(row["phase"])
        allowed_names = PHASE_ALLOWED_REFERENCES.get(phase)
        if not allowed_names:
            raise ValueError(f"unknown transition phase {phase}")

        projection = row["projection"]
        relational_alert = not any(
            projection_equal(projection, refs[name]) for name in allowed_names
        )

        observed_counts = state_counts(projection)
        allowed_counts = {
            state_counts(refs[name]) for name in allowed_names
        }
        legacy_alert = observed_counts not in allowed_counts

        if relational_alert:
            relational_alert_rows += 1
        if legacy_alert:
            legacy_alert_rows += 1
        if bool(row.get("known_clean_control")) and relational_alert:
            phase_clean_false_alert_rows += 1

        alerts.append(
            {
                "tick": tick,
                "phase": phase,
                "relational_alert": relational_alert,
                "legacy_count_status_alert": legacy_alert,
                "allowed_references": list(allowed_names),
                "observed_counts": list(observed_counts),
                "known_clean_control": bool(row.get("known_clean_control")),
            }
        )

    core = {
        "stage": STAGE,
        "schema": "stage35-transition-relational-verdict-v1",
        "seed": int(package["seed"]),
        "challenge_nonce": nonce,
        "collector_sequence": sequence,
        "collector_package_sha256": package_sha,
        "policy_sha256": POLICY_SHA256,
        "collector_public_key_sha256": COLLECTOR_PUBLIC_KEY_SHA256,
        "verifier_public_key_sha256": PUBLIC_KEY_SHA256,
        "verifier_service_revision": SERVICE_REVISION,
        "verifier_instance": INSTANCE_NAME,
        "freshness_anchor_service_revision": anchor_result[
            "service_revision"
        ],
        "freshness_anchor_last_sequence": anchor_result["last_sequence"],
        "telemetry_rows": len(observations),
        "relational_alert_rows": relational_alert_rows,
        "legacy_count_status_alert_rows": legacy_alert_rows,
        "known_clean_control_false_alert_rows": phase_clean_false_alert_rows,
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
    server_version = "Stage35TransitionRelationalVerifier/1.0"

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
                    "collector_public_key_sha256": COLLECTOR_PUBLIC_KEY_SHA256,
                    "verifier_public_key_sha256": PUBLIC_KEY_SHA256,
                    "service_revision": SERVICE_REVISION,
                    "verifier_instance": INSTANCE_NAME,
                    "freshness_anchor_endpoint": ANCHOR_ENDPOINT,
                    "client_authentication_required": True,
                    "verifier_key_origin": KEY_ORIGIN,
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
        print(
            f"STAGE35_VERIFIER_{INSTANCE_NAME}_HTTP",
            fmt % args,
            flush=True,
        )


def main():
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(
        "STAGE35_TRANSITION_VERIFIER_READY "
        f"instance={INSTANCE_NAME} port={port} policy={POLICY_SHA256} "
        f"collector_key={COLLECTOR_PUBLIC_KEY_SHA256} "
        f"verifier_key={PUBLIC_KEY_SHA256} key_origin={KEY_ORIGIN}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
