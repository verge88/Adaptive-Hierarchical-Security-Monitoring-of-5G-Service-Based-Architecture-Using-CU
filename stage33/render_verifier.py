"""Stage 33 external verifier service.

This service is intentionally deployed with auto-deploy disabled in a Render
workspace that is administratively separate from GitHub Actions. It keeps its
ECDSA private key only in the Render environment and independently recomputes
the Stage-29 invariant decision from raw, label-free telemetry.

GitHub sends observations; the service does not consume attack labels.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

STAGE = 33
MAX_BODY = 2_000_000


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def expected_epoch(tick: int) -> int:
    if tick < 30:
        return 0
    if tick < 40:
        return 1
    if tick < 45:
        return 2
    return 3


def expected_state(tick: int) -> tuple[int, int]:
    return (1, 1) if 30 <= tick < 40 else (2, 2)


PRIVATE_KEY_PEM = os.environ["STAGE33_PRIVATE_KEY_PEM"].encode("utf8")
APPROVED_POLICY_SHA256 = os.environ["STAGE33_APPROVED_POLICY_SHA256"].lower()
SERVICE_REVISION = os.environ.get("STAGE33_SERVICE_REVISION", "unrecorded")

if len(APPROVED_POLICY_SHA256) != 64:
    raise RuntimeError("STAGE33_APPROVED_POLICY_SHA256 must be SHA-256 hex")

PRIVATE_KEY = serialization.load_pem_private_key(PRIVATE_KEY_PEM, password=None)
if not isinstance(PRIVATE_KEY, ec.EllipticCurvePrivateKey):
    raise RuntimeError("Stage33 signing key must be an EC private key")

PUBLIC_KEY_PEM = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY_PEM).hexdigest()


def verify_request(doc: dict) -> dict:
    if int(doc.get("stage", -1)) != STAGE:
        raise ValueError("stage mismatch")
    if doc.get("policy_sha256", "").lower() != APPROVED_POLICY_SHA256:
        raise PermissionError("policy digest is not externally approved")

    nonce = str(doc.get("request_nonce", ""))
    if len(nonce) < 16 or len(nonce) > 256:
        raise ValueError("invalid request nonce")

    rows = doc.get("raw_telemetry")
    if not isinstance(rows, list) or not rows or len(rows) > 1000:
        raise ValueError("invalid raw telemetry")
    seed = int(rows[0]["seed"])

    alerts = []
    transition_alerts = 0
    mutation_like_ticks = 0

    for index, row in enumerate(rows):
        tick = int(row["tick"])
        if tick != index:
            raise ValueError("ticks must be contiguous from zero")
        if int(row["seed"]) != seed:
            raise ValueError("mixed seed")
        if int(row.get("baseline_epoch", expected_epoch(tick))) != expected_epoch(tick):
            raise ValueError("baseline epoch marker mismatch")

        consumer_count = int(row["consumer_nssf_count"])
        consumer_registered = int(row["consumer_registered_count"])
        witness_count = int(row["compromised_witness_nssf_count"])
        witness_registered = int(row["compromised_witness_registered_count"])

        if consumer_count != witness_count or consumer_registered != witness_registered:
            raise ValueError("common-source negative control is not colluding")

        expected_count, expected_registered = expected_state(tick)
        alert = (
            consumer_count != expected_count
            or consumer_registered != expected_registered
        )

        # Ticks 30..49 are the preregistered legitimate-transition validation
        # region. Any discrepancy here invalidates the run rather than being
        # silently counted as an attack.
        if 30 <= tick < 50 and alert:
            transition_alerts += 1

        if tick >= 50 and alert:
            mutation_like_ticks += 1

        alerts.append(
            {
                "tick": tick,
                "external_invariant_alert": bool(alert),
                "colluding_pair_alert": False,
            }
        )

    if transition_alerts:
        raise ValueError(
            f"legitimate transition region contained {transition_alerts} mismatches"
        )

    request_sha256 = hashlib.sha256(canonical_bytes(doc)).hexdigest()
    core = {
        "stage": STAGE,
        "service_revision": SERVICE_REVISION,
        "seed": seed,
        "request_nonce": nonce,
        "request_sha256": request_sha256,
        "policy_sha256": APPROVED_POLICY_SHA256,
        "public_key_sha256": PUBLIC_KEY_SHA256,
        "telemetry_rows": len(rows),
        "external_alert_rows": sum(
            int(row["external_invariant_alert"]) for row in alerts
        ),
        "colluding_pair_alert_rows": 0,
        "legitimate_transition_alert_rows": transition_alerts,
        "post_transition_mismatch_rows": mutation_like_ticks,
        "alerts": alerts,
    }
    signature = PRIVATE_KEY.sign(
        canonical_bytes(core),
        ec.ECDSA(hashes.SHA256()),
    )
    return {
        "verdict": core,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Stage33ExternalVerifier/1.0"

    def _json(self, status: int, doc: dict) -> None:
        body = json.dumps(doc, sort_keys=True).encode("utf8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(
                200,
                {
                    "stage": STAGE,
                    "status": "ok",
                    "service_revision": SERVICE_REVISION,
                    "approved_policy_sha256": APPROVED_POLICY_SHA256,
                    "public_key_sha256": PUBLIC_KEY_SHA256,
                },
            )
            return
        if self.path == "/public-key":
            self._json(
                200,
                {
                    "stage": STAGE,
                    "public_key_pem": PUBLIC_KEY_PEM.decode("ascii"),
                    "public_key_sha256": PUBLIC_KEY_SHA256,
                },
            )
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/verify":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("invalid content length")
            raw = self.rfile.read(length)
            doc = json.loads(raw)
            result = verify_request(doc)
            self._json(200, result)
        except PermissionError as ex:
            self._json(403, {"error": str(ex)})
        except Exception as ex:
            self._json(422, {"error": f"{type(ex).__name__}: {ex}"})

    def log_message(self, fmt, *args):
        print("STAGE33_HTTP", self.address_string(), fmt % args, flush=True)


def main():
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(
        "STAGE33_EXTERNAL_VERIFIER_READY "
        f"port={port} policy={APPROVED_POLICY_SHA256} "
        f"public_key_sha256={PUBLIC_KEY_SHA256}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
