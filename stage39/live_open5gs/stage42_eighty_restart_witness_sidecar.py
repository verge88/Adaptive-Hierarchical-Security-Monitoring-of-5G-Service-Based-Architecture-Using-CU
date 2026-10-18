"""Independent Stage42 80-restart witness sidecar. The ECDSA private key stays outside NF container.

The sidecar shares the host kernel and is NOT remote/hardware attestation.
It obtains running process UUIDs via /proc + the Stage38 native runtime UUID
file and checks direct SBI endpoints without querying NRF discovery.
"""
import argparse
import base64
import hashlib
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from external_witness import SLOTS, canonical_bytes, collect


def atomic_write(path, document):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    temp.replace(path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--control-dir", type=Path, required=True)
    ap.add_argument("--private-key", type=Path, required=True)
    ap.add_argument("--timeout-seconds", type=float, default=2400.0)
    args = ap.parse_args()
    key = serialization.load_pem_private_key(args.private_key.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise RuntimeError("ECDSA witness key required")
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_digest = hashlib.sha256(public_pem).hexdigest()
    args.control_dir.mkdir(parents=True, exist_ok=True)
    req_path = args.control_dir / "witness_request.json"
    response_path = args.control_dir / "witness_response.json"
    processed = set()
    deadline = time.monotonic() + args.timeout_seconds
    while time.monotonic() < deadline:
        if not req_path.exists():
            time.sleep(0.02)
            continue
        try:
            req = json.loads(req_path.read_text())
        except (ValueError, OSError):
            time.sleep(0.02)
            continue
        cycle = req.get("cycle")
        nonce = req.get("nonce")
        policy_hash = req.get("policy_sha256")
        if (
            not isinstance(cycle, int) or cycle < 0
            or not isinstance(nonce, str) or len(nonce) != 32
            or not isinstance(policy_hash, str) or len(policy_hash) != 64
        ):
            raise RuntimeError("invalid witness request")
        if cycle in processed:
            time.sleep(0.02)
            continue
        records = collect()
        if set(records) != set(SLOTS) or not all(
            r.get("process_alive") and r.get("direct_sbi_tcp_reachable")
            for r in records.values()
        ):
            time.sleep(0.08)
            continue
        doc = {
            "schema": "stage41-external-process-witness-v1",
            "cycle": cycle,
            "nonce": nonce,
            "policy_sha256": policy_hash,
            "issued_at_unix_ns": time.time_ns(),
            "source": "separate-container:proc-cmdline+native-runtime-uuid-file+direct-sbi-tcp",
            "nrf_discovery_used": False,
            "public_key_sha256": key_digest,
            "slots": {slot: records[slot] for slot in sorted(records)},
        }
        sig = key.sign(canonical_bytes(doc), ec.ECDSA(hashes.SHA256()))
        atomic_write(response_path, {
            "snapshot": doc, "signature_base64": base64.b64encode(sig).decode()
        })
        processed.add(cycle)
        print(f"sidecar signed cycle={cycle} slots={len(records)}", flush=True)
        if cycle >= 80:
            return
    raise RuntimeError(f"sidecar timed out; signed cycles={sorted(processed)}")


if __name__ == "__main__":
    main()
