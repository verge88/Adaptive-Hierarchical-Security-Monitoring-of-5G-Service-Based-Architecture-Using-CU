"""Stage 38 NF-side/deployment witness.

This process does not query NRF. It observes Open5GS runtime identity records
emitted at NF initialization, verifies the corresponding PID/configuration
slot, and checks the direct SBI listening socket before signing a snapshot.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

STAGE = 38
POLICY_SHA256 = os.environ["STAGE38_POLICY_SHA256"].lower()
TOKEN = os.environ["STAGE38_WITNESS_TOKEN"]
WITNESS_DIR = Path("/run/stage38/witness")

SLOTS = {
    "nssf1": {"type": "NSSF", "endpoint": "127.0.0.12", "config": "nssf1.yaml"},
    "nssf2": {"type": "NSSF", "endpoint": "127.0.0.13", "config": "nssf2.yaml"},
    "ausf1": {"type": "AUSF", "endpoint": "127.0.0.14", "config": "ausf1.yaml"},
    "ausf2": {"type": "AUSF", "endpoint": "127.0.0.15", "config": "ausf2.yaml"},
    "bsf1": {"type": "BSF", "endpoint": "127.0.0.16", "config": "bsf1.yaml"},
    "bsf2": {"type": "BSF", "endpoint": "127.0.0.17", "config": "bsf2.yaml"},
    "udm1": {"type": "UDM", "endpoint": "127.0.0.18", "config": "udm1.yaml"},
    "udm2": {"type": "UDM", "endpoint": "127.0.0.19", "config": "udm2.yaml"},
}
CONFIG_TO_SLOT = {v["config"]: k for k, v in SLOTS.items()}

_private_pem = os.environ["STAGE38_WITNESS_PRIVATE_KEY_PEM"].encode()
PRIVATE_KEY = serialization.load_pem_private_key(_private_pem, password=None)
if not isinstance(PRIVATE_KEY, ec.EllipticCurvePrivateKey):
    raise RuntimeError("witness key must be EC")
PUBLIC_KEY_PEM = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY_PEM).hexdigest()


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def authorized(header: str | None) -> bool:
    if not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[7:], TOKEN)


def tcp_reachable(host: str, port: int = 80) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def process_cmdline(pid: int) -> list[str] | None:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None
    return [x.decode(errors="replace") for x in raw.split(b"\0") if x]


def snapshot(nonce: str) -> dict:
    records = {}
    for path in WITNESS_DIR.glob("*.tsv"):
        try:
            pid_s, _nf_enum, nf_uuid = path.read_text().strip().split("\t")
            pid = int(pid_s)
        except Exception:
            continue
        cmd = process_cmdline(pid)
        if not cmd:
            continue
        config = None
        for i, value in enumerate(cmd[:-1]):
            if value == "-c":
                config = Path(cmd[i + 1]).name
                break
        slot = CONFIG_TO_SLOT.get(config or "")
        if not slot:
            continue
        manifest = SLOTS[slot]
        binary = Path(cmd[0]).name
        records[slot] = {
            "slot": slot,
            "nf_type": manifest["type"],
            "endpoint": manifest["endpoint"],
            "nf_instance_id": nf_uuid.lower(),
            "pid": pid,
            "binary": binary,
            "config": manifest["config"],
            "process_alive": True,
            "direct_sbi_tcp_reachable": tcp_reachable(manifest["endpoint"]),
        }

    core = {
        "stage": STAGE,
        "schema": "stage38-nf-side-witness-v1",
        "policy_sha256": POLICY_SHA256,
        "challenge_nonce": nonce,
        "slots": {k: records[k] for k in sorted(records)},
        "source": "nf_runtime_uuid+proc_cmdline+direct_sbi_socket",
        "nrf_discovery_used": False,
        "witness_public_key_sha256": PUBLIC_KEY_SHA256,
    }
    signature = PRIVATE_KEY.sign(
        canonical_bytes(core), ec.ECDSA(hashes.SHA256())
    )
    return {
        "snapshot": core,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }


class Handler(BaseHTTPRequestHandler):
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
                "witness_public_key_sha256": PUBLIC_KEY_SHA256,
                "nrf_discovery_used": False,
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
        if self.path != "/snapshot":
            self.send_json(404, {"error": "not found"})
            return
        if not authorized(self.headers.get("Authorization")):
            self.send_json(401, {"error": "witness authentication failed"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            doc = json.loads(self.rfile.read(length))
            nonce = str(doc["challenge_nonce"])
            if len(nonce) < 32 or len(nonce) > 256:
                raise ValueError("invalid nonce")
            self.send_json(200, snapshot(nonce))
        except Exception as ex:
            self.send_json(422, {"error": f"{type(ex).__name__}: {ex}"})

    def log_message(self, fmt, *args):
        print("STAGE38_WITNESS_HTTP", fmt % args, flush=True)


def main():
    WITNESS_DIR.mkdir(parents=True, exist_ok=True)
    port = int(os.environ.get("STAGE38_WITNESS_PORT", "10001"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(
        "STAGE38_WITNESS_READY "
        f"port={port} key={PUBLIC_KEY_SHA256} policy={POLICY_SHA256}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
