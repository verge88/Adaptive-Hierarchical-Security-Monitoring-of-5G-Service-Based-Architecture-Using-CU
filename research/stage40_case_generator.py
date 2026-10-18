"""Stage 40: fixed, labelled cases with independently MAC-bound witness claims.

This generator is a software fixture, not a live Open5GS attack or a remote
attestation implementation. The adversary can edit the NRF-facing profile,
not the lifecycle authorization, the approved policy or witness MAC key.
"""
import argparse
import copy
import hashlib
import json
import time
from pathlib import Path

from stage39_kie import FullProfilePolicy, default_profiles, hmac_hex

FAMILIES = (
    "benign_restart",
    "benign_restart_absence",
    "spoof_uuid_during_restart",
    "tamper_service_during_restart",
    "tamper_fqdn_during_restart",
    "missing_stable_during_restart",
    "duplicate_during_restart",
    "spoof_uuid_without_event",
)
BENIGN = {"benign_restart", "benign_restart_absence"}


def uuid_for(prefix, case_id):
    digest = hashlib.sha256((prefix + "|" + case_id).encode()).hexdigest()[:32]
    return "-".join((digest[:8], digest[8:12], digest[12:16], digest[16:20], digest[20:32]))


def build(policy, event_key, witness_key, now_ms):
    original, original_witnesses = default_profiles(policy)
    cases = []
    labels = []
    sequence = 0
    slots = sorted(policy.slots)
    for slot in slots:
        for family in FAMILIES:
            case_id = f"{slot}:{family}"
            observed = copy.deepcopy(original)
            witnesses = copy.deepcopy(original_witnesses)
            event = None
            moving = next(row for row in observed if row["slot"] == slot)
            if family == "spoof_uuid_without_event":
                moving["nfInstanceId"] = uuid_for("forged", case_id)
            else:
                sequence += 1
                payload = {
                    "operation": "restart", "slot": slot,
                    "sequence": sequence,
                    "nonce": hashlib.sha256(("event|" + case_id).encode()).hexdigest()[:32],
                    "issued_at_ms": now_ms, "max_window_ms": 60000,
                    "policy_sha256": policy.digest,
                }
                event = {"payload": payload, "hmac_sha256": hmac_hex(event_key, payload)}
                genuine_uuid = uuid_for("genuine", case_id)
                moving["nfInstanceId"] = genuine_uuid
                witnesses[slot]["nf_instance_id"] = genuine_uuid

                if family == "benign_restart_absence":
                    observed = [row for row in observed if row["slot"] != slot]
                    witnesses.pop(slot)
                elif family == "spoof_uuid_during_restart":
                    moving["nfInstanceId"] = uuid_for("forged", case_id)
                elif family == "tamper_service_during_restart":
                    moving["nfServices"].append({
                        "serviceName": "unapproved-stage40",
                        "scheme": "https", "status": "REGISTERED",
                        "versions": ["v1"],
                        "endpoints": [{"ip": "198.51.100.35", "port": 443, "transport": "TCP"}],
                    })
                elif family == "tamper_fqdn_during_restart":
                    moving["fqdn"] = "forged-stage40.invalid"
                elif family == "missing_stable_during_restart":
                    stable = next(other for other in slots if other != slot)
                    observed = [row for row in observed if row["slot"] != stable]
                    witnesses.pop(stable)
                elif family == "duplicate_during_restart":
                    observed.append(copy.deepcopy(moving))
                elif family != "benign_restart":
                    raise ValueError(family)

            witness_doc = {
                "case_id": case_id, "policy_sha256": policy.digest,
                "issued_at_ms": now_ms, "witnesses": witnesses,
            }
            cases.append({
                "case_id": case_id,
                "pre_profiles": copy.deepcopy(original),
                "observed_profiles": observed,
                "lifecycle": event,
                "signed_witness": {
                    "payload": witness_doc,
                    "hmac_sha256": hmac_hex(witness_key, witness_doc),
                },
            })
            labels.append({
                "case_id": case_id,
                "attacked": family not in BENIGN,
                "family": family,
                "target_slot": slot,
            })
    return cases, labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--event-key-file", type=Path, required=True)
    ap.add_argument("--witness-key-file", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    policy = FullProfilePolicy.load(args.policy)
    event_key = bytes.fromhex(args.event_key_file.read_text().strip())
    witness_key = bytes.fromhex(args.witness_key_file.read_text().strip())
    assert event_key != witness_key
    cases, labels = build(policy, event_key, witness_key, int(time.time() * 1000))
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "stage40_cases.json").write_text(
        json.dumps(cases, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.output / "stage40_private_labels.json").write_text(
        json.dumps(labels, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print("Generated", len(cases), "software cases; labels in a separate file")


if __name__ == "__main__":
    main()
