"""Stage 38 external blind orchestration client."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import time
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def canonical_bytes(doc) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def get_json(url: str):
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.loads(response.read())


def post_json(url: str, doc: dict, timeout: float = 480):
    req = urllib.request.Request(
        url,
        data=canonical_bytes(doc),
        headers={"Content-Type": "application/json"},
        method="POST",
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


def load_key(doc: dict, expected_sha: str):
    pem = doc["public_key_pem"].encode()
    digest = hashlib.sha256(pem).hexdigest()
    if digest != expected_sha.lower() or doc["public_key_sha256"] != digest:
        raise ValueError("public key fingerprint mismatch")
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("expected EC public key")
    return key, pem


def verify(key, doc: dict, signature_b64: str):
    key.verify(
        base64.b64decode(signature_b64, validate=True),
        canonical_bytes(doc),
        ec.ECDSA(hashes.SHA256()),
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--collector-endpoint", required=True)
    p.add_argument("--verifier-a-endpoint", required=True)
    p.add_argument("--policy-sha256-file", required=True)
    p.add_argument("--expected-collector-key-sha256", required=True)
    p.add_argument("--expected-verifier-key-sha256", required=True)
    p.add_argument("--expected-witness-key-sha256", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--labels-output", required=True)
    args = p.parse_args()

    collector = args.collector_endpoint.rstrip("/")
    verifier = args.verifier_a_endpoint.rstrip("/")
    policy = Path(args.policy_sha256_file).read_text().strip().lower()

    health = get_json(collector + "/health")
    if health.get("policy_sha256") != policy:
        raise ValueError("collector policy mismatch")
    if set(health.get("nf_types", [])) != {"NSSF", "AUSF", "BSF", "UDM"}:
        raise ValueError("collector multi-NF scope mismatch")
    if int(health.get("nf_instance_slots", 0)) != 8:
        raise ValueError("collector does not expose eight NF slots")
    if health.get("witness_uses_nrf_discovery") is not False:
        raise ValueError("witness is not independent of NRF discovery")

    collector_key, collector_pem = load_key(
        get_json(collector + "/public-key"),
        args.expected_collector_key_sha256,
    )
    verifier_key, verifier_pem = load_key(
        get_json(verifier + "/public-key"),
        args.expected_verifier_key_sha256,
    )
    witness_key, witness_pem = load_key(
        get_json(collector + "/witness-public-key"),
        args.expected_witness_key_sha256,
    )

    nonce = secrets.token_hex(32)
    status, result, round_trip_ms = post_json(
        collector + "/run",
        {
            "stage": 38,
            "seed": args.seed,
            "challenge_nonce": nonce,
            "policy_sha256": policy,
        },
    )
    if status != 200:
        raise RuntimeError(f"collector run failed HTTP {status}: {result}")

    package = result["telemetry_package"]
    collector_sig = result["collector_signature_base64"]
    verifier_result = result["verifier_result"]
    verdict = verifier_result["verdict"]
    verifier_sig = verifier_result["signature_base64"]
    labels = result["private_labels"]
    evidence = dict(result["evidence"])

    verify(collector_key, package, collector_sig)
    verify(verifier_key, verdict, verifier_sig)
    for label, bundle in package["witness_snapshots"].items():
        verify(witness_key, bundle["snapshot"], bundle["signature_base64"])
        if bundle["snapshot"]["snapshot_label"] != label:
            raise ValueError("witness label binding mismatch")
        if bundle["snapshot"]["challenge_nonce"] != nonce:
            raise ValueError("witness nonce binding mismatch")

    package_sha = hashlib.sha256(canonical_bytes(package)).hexdigest()
    if result["collector_package_sha256"] != package_sha:
        raise ValueError("collector package hash mismatch")
    if verdict["collector_package_sha256"] != package_sha:
        raise ValueError("verdict/package binding mismatch")
    if package["challenge_nonce"] != nonce or verdict["challenge_nonce"] != nonce:
        raise ValueError("challenge nonce mismatch")
    if int(package["seed"]) != args.seed or int(verdict["seed"]) != args.seed:
        raise ValueError("seed mismatch")
    if package["attack_labels_in_package"] is not False:
        raise ValueError("private labels entered verifier package")
    if verdict["attack_labels_received"] is not False:
        raise ValueError("verifier received private labels")
    if verdict["witness_signatures_verified"] is not True:
        raise ValueError("verifier did not verify witness signatures")
    if verdict["witness_reference_bindings_verified"] is not True:
        raise ValueError("verifier did not bind references to witness")

    tampered = json.loads(json.dumps(package))
    tampered["seed"] += 1
    try:
        verify(collector_key, tampered, collector_sig)
        raise AssertionError("tampered collector package verified")
    except InvalidSignature:
        pass

    tampered_verdict = json.loads(json.dumps(verdict))
    tampered_verdict["relational_alert_rows"] += 1
    try:
        verify(verifier_key, tampered_verdict, verifier_sig)
        raise AssertionError("tampered verifier verdict verified")
    except InvalidSignature:
        pass

    first_label = sorted(package["witness_snapshots"])[0]
    witness_bundle = package["witness_snapshots"][first_label]
    tampered_witness = json.loads(json.dumps(witness_bundle["snapshot"]))
    tampered_witness["snapshot_label"] += "-tampered"
    try:
        verify(witness_key, tampered_witness, witness_bundle["signature_base64"])
        raise AssertionError("tampered witness snapshot verified")
    except InvalidSignature:
        pass

    evidence.update({
        "orchestration_round_trip_ms": round_trip_ms,
        "collector_signature_verified_by_github": True,
        "verifier_signature_verified_by_github": True,
        "witness_signatures_verified_by_github": True,
        "collector_package_tamper_rejected_by_github": True,
        "verifier_verdict_tamper_rejected_by_github": True,
        "witness_snapshot_tamper_rejected_by_github": True,
        "collector_package_sha256": package_sha,
    })

    out = Path(args.output)
    labels_out = Path(args.labels_output)
    out.mkdir(parents=True, exist_ok=True)
    labels_out.mkdir(parents=True, exist_ok=True)
    (out / "telemetry_package.json").write_text(
        json.dumps(package, indent=2), encoding="utf8"
    )
    (out / "signed_verdict.json").write_text(
        json.dumps({
            "stage": 38,
            "seed": args.seed,
            "verdict": verdict,
            "signature_base64": verifier_sig,
        }, indent=2),
        encoding="utf8",
    )
    (out / "evidence.json").write_text(
        json.dumps(evidence, indent=2), encoding="utf8"
    )
    (out / "collector_public_key.pem").write_bytes(collector_pem)
    (out / "verifier_public_key.pem").write_bytes(verifier_pem)
    (out / "witness_public_key.pem").write_bytes(witness_pem)
    (labels_out / "private_labels.json").write_text(
        json.dumps(labels, indent=2), encoding="utf8"
    )

    print(
        "STAGE38_RUN_OK "
        f"seed={args.seed} alerts={verdict['relational_alert_rows']} "
        f"legacy={verdict['legacy_count_status_alert_rows']} "
        f"verifier_ms={evidence['verifier_latency_ms']:.2f}",
        flush=True,
    )


if __name__ == "__main__":
    main()
