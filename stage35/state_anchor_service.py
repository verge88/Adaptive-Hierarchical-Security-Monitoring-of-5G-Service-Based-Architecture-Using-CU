"""Stage 35 external freshness anchor.

The anchor is a separate Render process from both verifier instances. It owns
nonce/sequence replay state so a replay sent to another verifier process is
still rejected.

This is verifier-process-independent software state. It is deliberately not
described as TPM/TEE/HSM or crash-durable database state: restarting this anchor
resets the in-memory table.
"""
from __future__ import annotations

import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STAGE = 35
TOKEN = os.environ["STAGE35_ANCHOR_TOKEN"]
POLICY_SHA256 = os.environ["STAGE35_POLICY_SHA256"].lower()
SERVICE_REVISION = os.environ.get("STAGE35_ANCHOR_REVISION", "unrecorded")
MAX_BODY = 64_000

LOCK = threading.Lock()
SEEN_NONCES: dict[str, dict] = {}
LAST_SEQUENCE = 0


def authorized(header: str | None) -> bool:
    prefix = "Bearer "
    if not header or not header.startswith(prefix):
        return False
    return hmac.compare_digest(header[len(prefix):], TOKEN)


def claim(doc: dict) -> tuple[int, dict]:
    global LAST_SEQUENCE

    if int(doc.get("stage", -1)) != STAGE:
        return 422, {"error": "stage mismatch"}
    if doc.get("policy_sha256") != POLICY_SHA256:
        return 403, {"error": "policy mismatch"}

    nonce = str(doc.get("challenge_nonce", ""))
    sequence = int(doc.get("collector_sequence", -1))
    package_sha = str(doc.get("collector_package_sha256", ""))

    if len(nonce) < 32 or len(nonce) > 256:
        return 422, {"error": "invalid nonce"}
    if len(package_sha) != 64:
        return 422, {"error": "invalid package digest"}

    with LOCK:
        if nonce in SEEN_NONCES:
            previous = SEEN_NONCES[nonce]
            return 409, {
                "error": "nonce replay",
                "previous_sequence": previous["collector_sequence"],
                "last_sequence": LAST_SEQUENCE,
            }
        if sequence <= LAST_SEQUENCE:
            return 409, {
                "error": "sequence rollback",
                "last_sequence": LAST_SEQUENCE,
            }

        SEEN_NONCES[nonce] = {
            "collector_sequence": sequence,
            "collector_package_sha256": package_sha,
        }
        LAST_SEQUENCE = sequence
        return 200, {
            "stage": STAGE,
            "accepted": True,
            "challenge_nonce": nonce,
            "collector_sequence": sequence,
            "last_sequence": LAST_SEQUENCE,
            "accepted_nonce_count": len(SEEN_NONCES),
            "service_revision": SERVICE_REVISION,
        }


class Handler(BaseHTTPRequestHandler):
    server_version = "Stage35FreshnessAnchor/1.0"

    def send_json(self, status: int, doc: dict) -> None:
        body = json.dumps(doc, sort_keys=True).encode("utf8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/health":
            self.send_json(404, {"error": "not found"})
            return
        self.send_json(
            200,
            {
                "stage": STAGE,
                "status": "ok",
                "policy_sha256": POLICY_SHA256,
                "service_revision": SERVICE_REVISION,
                "state_scope": "external_process_memory",
                "last_sequence": LAST_SEQUENCE,
                "accepted_nonce_count": len(SEEN_NONCES),
            },
        )

    def do_POST(self):
        if self.path != "/claim":
            self.send_json(404, {"error": "not found"})
            return
        if not authorized(self.headers.get("Authorization")):
            self.send_json(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("invalid body length")
            doc = json.loads(self.rfile.read(length))
            status, result = claim(doc)
            self.send_json(status, result)
        except Exception as ex:
            self.send_json(422, {"error": f"{type(ex).__name__}: {ex}"})

    def log_message(self, fmt, *args):
        print("STAGE35_ANCHOR_HTTP", fmt % args, flush=True)


def main():
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(
        "STAGE35_FRESHNESS_ANCHOR_READY "
        f"port={port} policy={POLICY_SHA256} revision={SERVICE_REVISION}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
