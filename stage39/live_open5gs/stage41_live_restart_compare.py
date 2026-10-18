"""Stage41 live Open5GS restart / native NRF UUID-spoof paired experiment.

Three real NF subprocesses are terminated and relaunched. A separate container
signs newly collected /proc + runtime UUID observations with a private EC key
never mounted into this process. A native *Open5GS NRF C response hook* spoofs
the discovery UUID after registration converges. Two detection rules then see
the identical mutated HTTP/2 discovery response and signed lifecycle event.
"""
from __future__ import annotations
import argparse
import asyncio
import base64
import hashlib
import json
import os
import secrets
import signal
import subprocess
import statistics
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from live_probe import (
    EXPECTED_DISCOVERY, LIVE_POLICY_PATH, LOG, MUTATION_ENABLE,
    MUTATION_PLAN, MUTATION_ROOT, MUTATION_TARGET_SLOT,
    PROCESSES, ROOT, WITNESS, atomic_json_write,
    clean_discovery_snapshot, discover_document, load_live_policy,
    live_policy_alerts, row_with_endpoint, start, stop_all,
    validate_all_live_policy, verify_live_policy_signature, wait_tcp,
    canonical_bytes,
)

TARGETS = (("nssf1", "NSSF"), ("ausf1", "AUSF"), ("bsf1", "BSF"))


def verify_ec(signature_b64, message, pubkey):
    pubkey.verify(
        base64.b64decode(signature_b64, validate=True),
        canonical_bytes(message),
        ec.ECDSA(hashes.SHA256()),
    )


def validate_lifecycle(events, path, public, policy_digest):
    public_key = serialization.load_pem_public_key(public.read_bytes())
    expected_slots = [slot for slot, _ in TARGETS]
    seen = set()
    if len(events) != len(TARGETS):
        raise RuntimeError("unexpected lifecycle event count")
    for index, (event, slot) in enumerate(zip(events, expected_slots), 1):
        p = event["payload"]
        verify_ec(event["signature_base64"], p, public_key)
        if (
            p.get("schema") != "stage41-external-lifecycle-v1"
            or p.get("sequence") != index or p.get("slot") != slot
            or p.get("operation") != "restart"
            or p.get("policy_sha256") != policy_digest
            or not isinstance(p.get("nonce"), str)
            or p["nonce"] in seen
            or int(p.get("validity_seconds", 0)) != 600
        ):
            raise RuntimeError("invalid lifecycle authorization")
        seen.add(p["nonce"])
        if abs(time.time_ns()-int(p["issued_at_unix_ns"])) > 600_000_000_000:
            raise RuntimeError("stale lifecycle authorization")
    # Confirm modified-event signatures are actually rejected.
    changed = dict(events[0]["payload"])
    changed["slot"] = "invalid"
    tamper_rejected = False
    try:
        verify_ec(events[0]["signature_base64"], changed, public_key)
    except Exception:
        tamper_rejected = True
    if not tamper_rejected:
        raise RuntimeError("tampered lifecycle event accepted")
    return {
        "verified_events": len(events),
        "event_key_sha256": hashlib.sha256(public.read_bytes()).hexdigest(),
        "tampered_event_rejected": True,
    }


def verify_witness(bundle, pub, policy_digest, cycle, nonce):
    snapshot = bundle["snapshot"]
    public_pem = pub.read_bytes()
    public_key = serialization.load_pem_public_key(public_pem)
    verify_ec(bundle["signature_base64"], snapshot, public_key)
    if (
        snapshot.get("schema") != "stage41-external-process-witness-v1"
        or snapshot.get("cycle") != cycle or snapshot.get("nonce") != nonce
        or snapshot.get("policy_sha256") != policy_digest
        or snapshot.get("nrf_discovery_used") is not False
        or snapshot.get("public_key_sha256") != hashlib.sha256(public_pem).hexdigest()
        or abs(time.time_ns()-int(snapshot.get("issued_at_unix_ns", 0))) > 15_000_000_000
    ):
        raise RuntimeError("incorrect/stale witness context")
    slots = snapshot.get("slots")
    if not isinstance(slots, dict) or set(slots) != set(PROCESSES):
        raise RuntimeError("incomplete independent witness snapshot")
    for slot, (_, _, nf_type, endpoint) in PROCESSES.items():
        record = slots[slot]
        if (
            record.get("nf_type") != nf_type or record.get("endpoint") != endpoint
            or record.get("process_alive") is not True
            or record.get("direct_sbi_tcp_reachable") is not True
            or not record.get("nf_instance_id")
            or int(record.get("pid", 0)) <= 0
        ):
            raise RuntimeError("invalid direct runtime witness for "+slot)
    normalized = {
        slot: {**record, "tcp_reachable": record["direct_sbi_tcp_reachable"]}
        for slot, record in slots.items()
    }
    return normalized


def tamper_witness_must_fail(bundle, pub):
    fake = json.loads(json.dumps(bundle))
    fake["snapshot"]["slots"]["nssf1"]["nf_instance_id"] = "forged-uuid"
    key = serialization.load_pem_public_key(pub.read_bytes())
    try:
        verify_ec(fake["signature_base64"], fake["snapshot"], key)
    except Exception:
        return True
    raise RuntimeError("witness signature did not reject tampering")


def request_sidecar(control, pub, digest, cycle, timeout=35):
    request_path = control/"witness_request.json"
    response_path = control/"witness_response.json"
    response_path.unlink(missing_ok=True)
    nonce = secrets.token_hex(16)
    atomic_json_write(request_path, {
        "cycle": cycle,
        "nonce": nonce,
        "policy_sha256": digest,
    })
    deadline = time.monotonic()+timeout
    last = None
    while time.monotonic() < deadline:
        if response_path.exists():
            try:
                bundle = json.loads(response_path.read_text())
                witness = verify_witness(bundle, pub, digest, cycle, nonce)
                return witness, bundle
            except Exception as error:
                last = repr(error)
        time.sleep(0.03)
    raise RuntimeError(f"sidecar cycle {cycle} failed: {last}")


async def await_live_convergence(nf_type, slot, witness, policy, timeout=30):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            document = await discover_document(nf_type)
            rows = document["nfInstances"]
            alerts = live_policy_alerts(nf_type, rows, witness, policy, True)
            expected_count = EXPECTED_DISCOVERY[nf_type]
            profile = row_with_endpoint(rows, PROCESSES[slot][3])
            verified_uuid = witness[slot]["nf_instance_id"]
            if (
                len(rows) == expected_count
                and not alerts
                and profile is not None
                and str(profile.get("nfInstanceId", "")).lower() == verified_uuid
            ):
                return rows
            last = {"counts": len(rows), "alerts": alerts,
                    "discovery_uuid": profile.get("nfInstanceId") if profile else None,
                    "witness_uuid": verified_uuid}
        except Exception as exc:
            last = repr(exc)
        await asyncio.sleep(0.15)
    raise RuntimeError(f"live NRF not converged after restart {slot}: {last}")


def metrics(rows, method):
    tp = fn = fp = tn = 0
    for r in rows:
        truth = r["kind"] == "native_nrf_uuid_spoof"
        alert = bool(r["decisions"][method])
        if truth and alert:
            tp += 1
        elif truth and not alert:
            fn += 1
        elif not truth and alert:
            fp += 1
        else:
            tn += 1
    return {"TP": tp, "FN": fn, "FP": fp, "TN": tn,
            "recall": tp/(tp+fn), "FPR": fp/(fp+tn)}


def kill_and_restart(slot, processes):
    old = processes[slot]
    old_pid = old.pid
    if old.poll() is not None:
        raise RuntimeError("NF died unexpectedly before authorized restart")
    os.killpg(old_pid, signal.SIGTERM)
    try:
        old.wait(timeout=8)
    except subprocess.TimeoutExpired:
        os.killpg(old_pid, signal.SIGKILL)
        old.wait(timeout=5)
    if old.poll() is None:
        raise RuntimeError("old NF is not dead")
    new = start(slot)
    processes[slot] = new
    if new.pid == old_pid:
        raise RuntimeError("old and new PID unexpectedly identical")
    wait_tcp(PROCESSES[slot][3], seconds=20)
    return old_pid, new.pid


async def main_async(args):
    args.output.mkdir(parents=True, exist_ok=True)
    LOG.mkdir(parents=True, exist_ok=True)
    WITNESS.mkdir(parents=True, exist_ok=True)
    MUTATION_ROOT.mkdir(parents=True, exist_ok=True)
    MUTATION_ENABLE.unlink(missing_ok=True)
    MUTATION_PLAN.unlink(missing_ok=True)
    for file in WITNESS.glob("*.tsv"):
        file.unlink()
    policy = load_live_policy()
    policy_digest = hashlib.sha256(LIVE_POLICY_PATH.read_bytes()).hexdigest()
    policy_signature = verify_live_policy_signature(args.policy_public, args.policy_signature)
    events = json.loads(args.lifecycle_events.read_text())
    lifecycle_proof = validate_lifecycle(
        events, args.lifecycle_events, args.lifecycle_public, policy_digest
    )
    processes = {}
    evidence = []
    restarts = []
    signed_snapshots = []
    try:
        processes["nrf1"] = start("nrf1")
        wait_tcp(PROCESSES["nrf1"][3], seconds=20)
        processes["scp1"] = start("scp1")
        wait_tcp(PROCESSES["scp1"][3], seconds=20)
        for slot in PROCESSES:
            if slot not in ("nrf1", "scp1"):
                processes[slot] = start(slot)
                await asyncio.sleep(0.12)
        for slot in PROCESSES:
            wait_tcp(PROCESSES[slot][3], seconds=20)

        clean = None
        deadline = time.monotonic()+40
        while time.monotonic() < deadline:
            try:
                clean = await clean_discovery_snapshot()
                break
            except Exception:
                await asyncio.sleep(0.2)
        if clean is None:
            raise RuntimeError("initial live discovery not converged")
        first_witness, first_bundle = request_sidecar(
            args.control_dir, args.witness_public, policy_digest, 0
        )
        if not tamper_witness_must_fail(first_bundle, args.witness_public):
            raise RuntimeError("witness tampering test failed")
        if validate_all_live_policy(clean, first_witness, policy):
            raise RuntimeError("initial live policy not clean")
        signed_snapshots.append(first_bundle)

        # Loaded once by native NRF C instrumentation, tick 0 for each type.
        plan = []
        for slot, typ in TARGETS:
            code = MUTATION_TARGET_SLOT[typ][1]
            plan.append(f"{typ}\t0\tidentity_replacement\t{code*100+1}")
        MUTATION_PLAN.write_text("\n".join(plan)+"\n")

        for index, (slot, nf_type) in enumerate(TARGETS, 1):
            prior = signed_snapshots[-1]["snapshot"]["slots"][slot]
            event = events[index-1]
            if event["payload"]["slot"] != slot:
                raise RuntimeError("wrong signed restart authorization")
            old_pid, new_pid = kill_and_restart(slot, processes)
            signed_witness, bundle = request_sidecar(
                args.control_dir, args.witness_public, policy_digest, index
            )
            actual = signed_witness[slot]
            if (
                old_pid != int(prior["pid"])
                or new_pid != int(actual["pid"])
                or str(actual["nf_instance_id"]).lower()
                   == str(prior["nf_instance_id"]).lower()
            ):
                raise RuntimeError("true NF PID + UUID rotation not demonstrated")
            fresh_rows = await await_live_convergence(
                nf_type, slot, signed_witness, policy
            )
            baseline_clean = live_policy_alerts(
                nf_type, fresh_rows, signed_witness, policy, include_witness=False
            )
            proposal_clean = live_policy_alerts(
                nf_type, fresh_rows, signed_witness, policy, include_witness=True
            )
            if baseline_clean or proposal_clean:
                raise RuntimeError("benign actual restart incorrectly rejected")
            evidence.append({
                "cycle": index, "slot": slot, "kind": "benign_real_restart",
                "decisions": {"lifecycle_full_policy": False,
                              "policy_plus_independent_witness": False},
            })
            restarts.append({
                "slot": slot, "nf_type": nf_type, "operation": "signed_restart",
                "old_pid": old_pid, "new_pid": new_pid,
                "old_runtime_uuid": prior["nf_instance_id"],
                "new_runtime_uuid": actual["nf_instance_id"],
                "signed_lifecycle_sequence": event["payload"]["sequence"],
                "fresh_witness_cycle": index,
                "signed_witness_public_key_sha256": bundle["snapshot"]["public_key_sha256"],
                "nrf_registered_new_uuid": True,
            })
            signed_snapshots.append(bundle)
            # Native response tampering, not rewriting Python return values.
            MUTATION_ENABLE.touch()
            try:
                mutated = await discover_document(nf_type)
            finally:
                MUTATION_ENABLE.unlink(missing_ok=True)
            if not isinstance(mutated.get("stage39MutationMonotonicNs"), (int,float)):
                raise RuntimeError("real Open5GS NRF response mutation marker missing")
            spoofed_rows = mutated["nfInstances"]
            spoofed = row_with_endpoint(spoofed_rows, PROCESSES[slot][3])
            if spoofed is None:
                raise RuntimeError("native NRF response lost target endpoint")
            spoofed_uuid = str(spoofed.get("nfInstanceId", "")).lower()
            if spoofed_uuid == actual["nf_instance_id"]:
                raise RuntimeError("native NRF did not replace discovered instance UUID")
            baseline_alerts = live_policy_alerts(
                nf_type, spoofed_rows, signed_witness, policy,
                include_witness=False
            )
            proposal_alerts = live_policy_alerts(
                nf_type, spoofed_rows, signed_witness, policy,
                include_witness=True
            )
            if baseline_alerts or f"witness_uuid:{slot}" not in proposal_alerts:
                raise RuntimeError(
                    f"expected real-signed-witness difference absent {slot}: "
                    f"baseline={baseline_alerts}, proposed={proposal_alerts}"
                )
            evidence.append({
                "cycle": index, "slot": slot, "kind": "native_nrf_uuid_spoof",
                "nrf_mutation_timestamp_ns": mutated["stage39MutationMonotonicNs"],
                "actual_runtime_uuid": actual["nf_instance_id"],
                "spoofed_discovery_uuid": spoofed_uuid,
                "decisions": {"lifecycle_full_policy": bool(baseline_alerts),
                              "policy_plus_independent_witness": bool(proposal_alerts)},
                "baseline_alerts": baseline_alerts,
                "proposed_alerts": proposal_alerts,
            })
            # Native hook must not poison persisted NRF records.
            await await_live_convergence(nf_type, slot, signed_witness, policy)

        report = {
            "kind": "live Open5GS v2.7.6, three real NF process restarts + native NRF UUID response spoof",
            "live_processes": len(processes),
            "real_restarts": len(restarts),
            "independently_signed_runtime_snapshots": len(signed_snapshots),
            "native_nrf_mutations_observed": sum(
                r["kind"] == "native_nrf_uuid_spoof" for r in evidence
            ),
            "signed_lifecycle": lifecycle_proof,
            "signed_policy": policy_signature,
            "witness_key_sha256": signed_snapshots[0]["snapshot"]["public_key_sha256"],
            "mutated_witness_signature_rejected": True,
            "restarts": restarts,
            "metrics": {
                method: metrics(evidence, method)
                for method in ("lifecycle_full_policy", "policy_plus_independent_witness")
            },
            "cases": evidence,
            "limitations": [
                "Three selected NF instances were truly restarted; not all 13 slots.",
                "The attacker was a research-only Open5GS NRF C discovery-response hook, not a real attacker.",
                "Independent witness signs /proc+native runtime UUID records but shares the same runner kernel and node.",
                "The baseline intentionally lacks witness observations. With the same witness, a strong baseline can match.",
                "NF start/stop managed by authorized research driver; signed events pre-created by separate controller key.",
                "Only 3 paired positive and 3 benign outcomes: no population-level sensitivity inference.",
            ],
        }
        args.output.joinpath("stage41_report.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False)+"\n"
        )
        args.output.joinpath("stage41_witness_snapshots.json").write_text(
            json.dumps(signed_snapshots, indent=2, ensure_ascii=False)+"\n"
        )
        lines = [
            "# Stage41 live Open5GS restart + signed witnesses",
            "",
            f"- Real NF restarts with PID and runtime-UUID changes: {len(restarts)}",
            f"- Independent ECDSA runtime witness snapshots: {len(signed_snapshots)}",
            f"- Native NRF C-hook UUID spoof observations: {report['native_nrf_mutations_observed']}",
            f"- Full lifecycle policy: {report['metrics']['lifecycle_full_policy']}",
            f"- Policy + independent witness: {report['metrics']['policy_plus_independent_witness']}",
            "",
            "See stage41_report.json for signatures, per-case evidence and limits."
        ]
        args.output.joinpath("STAGE41_RESULT.md").write_text("\n".join(lines)+"\n")
        print("\n".join(lines), flush=True)
        if report["metrics"]["policy_plus_independent_witness"]["FN"] or report["metrics"]["policy_plus_independent_witness"]["FP"]:
            raise RuntimeError("proposed method missed or falsely alarmed")
        if report["metrics"]["lifecycle_full_policy"]["FN"] != len(TARGETS):
            raise RuntimeError("strong policy baseline unexpected matrix")
    finally:
        MUTATION_ENABLE.unlink(missing_ok=True)
        MUTATION_PLAN.unlink(missing_ok=True)
        stop_all(processes)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--control-dir", type=Path, required=True)
    parser.add_argument("--witness-public", type=Path, required=True)
    parser.add_argument("--policy-public", type=Path, required=True)
    parser.add_argument("--policy-signature", type=Path, required=True)
    parser.add_argument("--lifecycle-public", type=Path, required=True)
    parser.add_argument("--lifecycle-events", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
