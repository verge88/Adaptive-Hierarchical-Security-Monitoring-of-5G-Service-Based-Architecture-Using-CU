"""Stage41 independent lifecycle authority, run outside the Open5GS container."""
import argparse
import base64
import hashlib
import json
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def canon(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--key", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    key = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
    policy_digest = hashlib.sha256(args.policy.read_bytes()).hexdigest()
    slots = ("nssf1", "ausf1", "bsf1")
    actual_policy = json.loads(args.policy.read_text())
    for slot in slots:
        if slot not in actual_policy["slots"]:
            raise RuntimeError("slot missing in live policy: " + slot)
    events = []
    for sequence, slot in enumerate(slots, 1):
        payload = {
            "schema": "stage41-external-lifecycle-v1",
            "sequence": sequence,
            "operation": "restart",
            "slot": slot,
            "nonce": secrets.token_hex(16),
            "issued_at_unix_ns": time.time_ns(),
            "policy_sha256": policy_digest,
            "validity_seconds": 600,
        }
        sig = key.sign(canon(payload), ec.ECDSA(hashes.SHA256()))
        events.append({"payload": payload, "signature_base64": base64.b64encode(sig).decode()})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(events, indent=2) + "\n")
    print("issued signed lifecycle authorizations", [x["payload"]["slot"] for x in events])


if __name__ == "__main__":
    main()
