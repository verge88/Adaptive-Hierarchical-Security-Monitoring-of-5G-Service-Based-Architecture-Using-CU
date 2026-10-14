"""Stage 34 external relational verifier.

This service consumes only signed telemetry from the external Stage-34
collector. It never receives private attack labels. It verifies the collector
signature, enforces process-lifetime nonce/sequence freshness, compares
identity-bound relational projections against the collector-frozen clean
baseline, and signs its own verdict.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

STAGE = 34
MAX_BODY = 5_000_000

APPROVED_POLICY_SHA256 = os.environ["STAGE34_POLICY_SHA256"].lower()
SERVICE_REVISION = os.environ.get("STAGE34_VERIFIER_REVISION", "unrecorded")

collector_public_pem = os.environ["STAGE34_COLLECTOR_PUBLIC_KEY_PEM"].encode("utf8")
COLLECTOR_PUBLIC_KEY = serialization.load_pem_public_key(collector_public_pem)
if not isinstance(COLLECTOR_PUBLIC_KEY, ec.EllipticCurvePublicKey):
    raise RuntimeError("collector public key must be EC")
COLLECTOR_PUBLIC_KEY_SHA256 = hashlib.sha256(collector_public_pem).hexdigest()
PINNED_COLLECTOR_PUBLIC_KEY_SHA256 = os.environ[
    "STAGE34_COLLECTOR_PUBLIC_KEY_SHA256"
].lower()
if COLLECTOR_PUBLIC_KEY_SHA256 != PINNED_COLLECTOR_PUBLIC_KEY_SHA256:
    raise RuntimeError("collector public-key fingerprint mismatch at startup")

verifier_private_pem = os.environ["STAGE34_VERIFIER_PRIVATE_KEY_PEM"].encode("utf8")
VERIFIER_PRIVATE_KEY = serialization.load_pem_private_key(
    verifier_private_pem, password=None
)
if not isinstance(VERIFIER_PRIVATE_KEY, ec.EllipticCurvePrivateKey):
    raise RuntimeError("verifier private key must be EC")
VERIFIER_PUBLIC_KEY_PEM = VERIFIER_PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
VERIFIER_PUBLIC_KEY_SHA256 = hashlib.sha256(
    VERIFIER_PUBLIC_KEY_PEM
).hexdigest()

STATE_LOCK = threading.Lock()
SEEN_NONCES: set[str] = set()
LAST_COLLECTOR_SEQUENCE = 0


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def projection_diff(baseline: dict, observed: dict) -> dict:
    base_profiles = baseline.get("profiles", {})
    obs_profiles = observed.get("profiles", {})
    base_keys = set(base_profiles)
    obs_keys = set(obs_profiles)

    changed = {}
    for nf_id in sorted(base_keys & obs_keys):
        if canonical_bytes(base_profiles[nf_id]) != canonical_bytes(
            obs_profiles[nf_id]
        ):
            fields = []
            all_fields = set(base_profiles[nf_id]) | set(obs_profiles[nf_id])
            for field in sorted(all_fields):
                if canonical_bytes(base_profiles[nf_id].get(field)) != canonical_bytes(
                    obs_profiles[nf_id].get(field)
                ):
                    fields.append(field)
            changed[nf_id] = fields

    return {
        "missing_ids": sorted(base_keys - obs_keys),
        "unexpected_ids": sorted(obs_keys - base_keys),
        "changed_fields": changed,
        "duplicate_ids": observed.get("duplicateIds", []),
    }


def diff_is_alert(diff: dict) -> bool:
    return bool(
        diff["missing_ids"]
        or diff["unexpected_ids"]
        or diff["changed_fields"]
        or diff["duplicate_ids"]
    )


def verify_collector_signature(package: dict, signature_b64: str) -> None:
    signature = base64.b64decode(signature_b64, validate=True)
    COLLECTOR_PUBLIC_KEY.verify(
        signature,
        canonical_bytes(package),
        ec.ECDSA(hashes.SHA256()),
    )


def verify_package(package: dict, signature_b64: str) -> dict:
    global LAST_COLLECTOR_SEQUENCE

    if int(package.get("stage", -1)) != STAGE:
        raise ValueError("package stage mismatch")
    if package.get("schema") != "stage34-external-relational-telemetry-v1":
        raise ValueError("package schema mismatch")
    if package.get("policy_sha256") != APPROVED_POLICY_SHA256:
        raise PermissionError("package policy is not approved")
    if package.get("collector_public_key_sha256") != COLLECTOR_PUBLIC_KEY_SHA256:
        raise ValueError("package collector-key fingerprint mismatch")
    if package.get("attack_labels_in_package") is not False:
        raise ValueError("attack labels are forbidden in verifier package")

    verify_collector_signature(package, signature_b64)

    nonce = str(package.get("challenge_nonce", ""))
    sequence = int(package.get("collector_sequence", -1))
    if len(nonce) < 32 or len(nonce) > 256:
        raise ValueError("invalid collector challenge nonce")

    with STATE_LOCK:
        if nonce in SEEN_NONCES:
            raise ValueError("collector nonce replay")
        if sequence <= LAST_COLLECTOR_SEQUENCE:
            raise ValueError(
                f"collector sequence rollback {sequence} <= {LAST_COLLECTOR_SEQUENCE}"
            )
        SEEN_NONCES.add(nonce)
        LAST_COLLECTOR_SEQUENCE = sequence

    baseline_doc = package.get("baseline")
    observations = package.get("observations")
    if not isinstance(baseline_doc, dict) or not isinstance(observations, list):
        raise ValueError("missing relational baseline/observations")
    baseline = baseline_doc.get("projection")
    if not isinstance(baseline, dict):
        raise ValueError("missing baseline projection")

    base_count = int(baseline_doc.get("count", -1))
    base_registered = int(baseline_doc.get("registered", -1))
    if (base_count, base_registered) != (2, 2):
        raise ValueError("unexpected Stage34 clean baseline cardinality")

    alerts = []
    legacy_alert_rows = 0
    relational_alert_rows = 0

    for expected_tick, row in enumerate(observations):
        tick = int(row["tick"])
        if tick != expected_tick:
            raise ValueError("non-contiguous observation ticks")

        legacy_alert = (
            int(row["legacy_nssf_count"]) != base_count
            or int(row["legacy_registered_count"]) != base_registered
        )
        if legacy_alert:
            legacy_alert_rows += 1

        observed = row.get("projection")
        if not isinstance(observed, dict):
            raise ValueError("observation projection missing")
        diff = projection_diff(baseline, observed)
        relational_alert = diff_is_alert(diff)
        if relational_alert:
            relational_alert_rows += 1

        alerts.append(
            {
                "tick": tick,
                "legacy_count_status_alert": legacy_alert,
                "relational_alert": relational_alert,
                "relational_diff": diff,
            }
        )

    package_sha = hashlib.sha256(canonical_bytes(package)).hexdigest()
    core = {
        "stage": STAGE,
        "schema": "stage34-external-relational-verdict-v1",
        "seed": int(package["seed"]),
        "challenge_nonce": nonce,
        "collector_sequence": sequence,
        "collector_package_sha256": package_sha,
        "policy_sha256": APPROVED_POLICY_SHA256,
        "collector_public_key_sha256": COLLECTOR_PUBLIC_KEY_SHA256,
        "verifier_public_key_sha256": VERIFIER_PUBLIC_KEY_SHA256,
        "verifier_service_revision": SERVICE_REVISION,
        "telemetry_rows": len(observations),
        "legacy_count_status_alert_rows": legacy_alert_rows,
        "relational_alert_rows": relational_alert_rows,
        "alerts": alerts,
        "attack_labels_received": False,
        "freshness": {
            "nonce_unique_in_process": True,
            "collector_sequence_monotonic": True,
        },
    }
    signature = VERIFIER_PRIVATE_KEY.sign(
        canonical_bytes(core), ec.ECDSA(hashes.SHA256())
    )
    return {
        "verdict": core,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Stage34ExternalRelationalVerifier/1.0"

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
                    "policy_sha256": APPROVED_POLICY_SHA256,
                    "collector_public_key_sha256": COLLECTOR_PUBLIC_KEY_SHA256,
                    "verifier_public_key_sha256": VERIFIER_PUBLIC_KEY_SHA256,
                    "service_revision": SERVICE_REVISION,
                    "last_collector_sequence": LAST_COLLECTOR_SEQUENCE,
                },
            )
            return
        if self.path == "/public-key":
            self._send(
                200,
                {
                    "stage": STAGE,
                    "public_key_pem": VERIFIER_PUBLIC_KEY_PEM.decode("ascii"),
                    "public_key_sha256": VERIFIER_PUBLIC_KEY_SHA256,
                },
            )
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/verify":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("invalid body length")
            request = json.loads(self.rfile.read(length))
            package = request["telemetry_package"]
            signature = request["collector_signature_base64"]
            result = verify_package(package, signature)
            self._send(200, result)
        except PermissionError as ex:
            self._send(403, {"error": str(ex)})
        except Exception as ex:
            self._send(422, {"error": f"{type(ex).__name__}: {ex}"})

    def log_message(self, fmt, *args):
        print("STAGE34_VERIFIER_HTTP", fmt % args, flush=True)


def main():
    port = int(os.environ.get("PORT", "10000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(
        "STAGE34_EXTERNAL_RELATIONAL_VERIFIER_READY "
        f"port={port} policy={APPROVED_POLICY_SHA256} "
        f"collector_key={COLLECTOR_PUBLIC_KEY_SHA256} "
        f"verifier_key={VERIFIER_PUBLIC_KEY_SHA256} "
        f"revision={SERVICE_REVISION}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
