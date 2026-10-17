from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import statistics
import time
from pathlib import Path

from stage39_kie import (
    FullProfilePolicy,
    StreamRelationalVerifier,
    default_profiles,
    hmac_hex,
    mutate,
    normalize_profile,
    sha256_json,
)


class LifecycleAuthorizationError(ValueError):
    pass


class LifecycleAuthority:
    def __init__(self,key,policy_digest):
        self.key=key
        self.policy_digest=policy_digest
        self.last_sequence=0
        self.nonces=set()

    def verify(self,envelope):
        payload=envelope.get("payload")
        mac=str(envelope.get("hmac_sha256",""))
        if not isinstance(payload,dict):
            raise LifecycleAuthorizationError("missing lifecycle payload")
        if not hmac.compare_digest(mac,hmac_hex(self.key,payload)):
            raise LifecycleAuthorizationError("invalid lifecycle signature")
        sequence=int(payload.get("sequence",-1))
        if sequence<=self.last_sequence:
            raise LifecycleAuthorizationError("replayed lifecycle sequence")
        nonce=str(payload.get("nonce",""))
        if not nonce or nonce in self.nonces:
            raise LifecycleAuthorizationError("replayed lifecycle nonce")
        if payload.get("policy_sha256")!=self.policy_digest:
            raise LifecycleAuthorizationError("lifecycle policy mismatch")
        if payload.get("operation") not in {"stop","start","restart"}:
            raise LifecycleAuthorizationError("invalid lifecycle operation")
        self.last_sequence=sequence
        self.nonces.add(nonce)
        if len(self.nonces)>10000:
            self.nonces=set(list(self.nonces)[-5000:])
        return payload


def canonical_state(profiles):
    return sorted(
        [normalize_profile(row) for row in profiles],
        key=lambda row:(row["slot"],row["nfInstanceId"]),
    )


def profiles_by_slot(profiles):
    return {row["slot"]:normalize_profile(row) for row in profiles}


def signed_full_policy_alert(
    policy,pre_profiles,observed,operation,moving_slot,witnesses=None
):
    pre=profiles_by_slot(pre_profiles)
    obs=profiles_by_slot(observed)
    alerts=[]
    for slot,row in pre.items():
        if slot==moving_slot:
            continue
        if slot not in obs:
            alerts.append("missing_stable:"+slot)
        elif obs[slot]!=row:
            alerts.append("stable_changed:"+slot)
    if moving_slot in obs:
        row=obs[moving_slot]
        if not policy.matches(row):
            alerts.append("moving_semantic:"+moving_slot)
    for slot,row in obs.items():
        if slot not in policy.slots:
            alerts.append("unknown_slot:"+slot)
        elif slot not in pre and not (
            operation=="start" and slot==moving_slot
        ):
            alerts.append("unexpected_slot:"+slot)
        elif not policy.matches(row):
            alerts.append("semantic:"+slot)
        if witnesses is not None and slot in witnesses:
            w=witnesses[slot]
            if str(row.get("nfInstanceId","")).lower()!=str(
                w.get("nf_instance_id","")
            ).lower():
                alerts.append("witness_uuid:"+slot)
    ids=[row["nfInstanceId"] for row in obs.values()]
    if len(ids)!=len(set(ids)):
        alerts.append("duplicate_nfInstanceId")
    return sorted(set(alerts))


def count_status_alert(pre_profiles,observed):
    if len(pre_profiles)!=len(observed):
        return True
    return any(
        normalize_profile(row)["nfStatus"]!="REGISTERED"
        for row in observed
    )


def next_uuid(slot,sequence):
    raw=hashlib.sha256(
        f"stage39-orchestrator:{slot}:{sequence}".encode()
    ).hexdigest()[:32]
    return (
        f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-"
        f"{raw[16:20]}-{raw[20:32]}"
    )


def read_jsonl(path):
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def compute_metrics(decisions,labels):
    joined=[]
    by_seq={int(row["sequence"]):row for row in labels}
    for row in decisions:
        label=by_seq[int(row["sequence"])]
        joined.append((row,label))
    methods=sorted(decisions[0]["alerts"])
    out={}
    for method in methods:
        tp=fp=tn=fn=0
        for decision,label in joined:
            alert=bool(decision["alerts"][method])
            attacked=bool(label["attacked"])
            if attacked and alert: tp+=1
            elif attacked and not alert: fn+=1
            elif not attacked and alert: fp+=1
            else: tn+=1
        out[method]={
            "TP":tp,"FN":fn,"FP":fp,"TN":tn,
            "recall":tp/(tp+fn) if tp+fn else None,
            "false_positive_rate":fp/(fp+tn) if fp+tn else None,
        }
    return out


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--policy",type=Path,required=True)
    ap.add_argument("--events",type=Path,required=True)
    ap.add_argument("--labels",type=Path,required=True)
    ap.add_argument("--key-hex",required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)

    policy=FullProfilePolicy.load(args.policy)
    events=read_jsonl(args.events)
    labels=read_jsonl(args.labels)
    key=bytes.fromhex(args.key_hex)
    authority=LifecycleAuthority(key,policy.digest)
    profiles,witnesses=default_profiles(policy)
    verifier=StreamRelationalVerifier(policy)
    decisions=[]
    auth_latencies=[]

    label_by_seq={int(row["sequence"]):row for row in labels}
    if len(label_by_seq)!=len(events):
        raise RuntimeError("event/label cardinality mismatch")

    tampered=copy.deepcopy(events[0])
    tampered["payload"]["operation"]="stop"
    try:
        LifecycleAuthority(key,policy.digest).verify(tampered)
        raise RuntimeError("tampered lifecycle event accepted")
    except LifecycleAuthorizationError:
        pass

    first=copy.deepcopy(events[0])
    replay_authority=LifecycleAuthority(key,policy.digest)
    replay_authority.verify(first)
    try:
        replay_authority.verify(first)
        raise RuntimeError("lifecycle replay accepted")
    except LifecycleAuthorizationError:
        pass

    for envelope in events:
        t0=time.perf_counter_ns()
        event=authority.verify(envelope)
        auth_latencies.append((time.perf_counter_ns()-t0)/1_000_000)
        sequence=int(event["sequence"])
        slot=str(event["slot"])
        operation=str(event["operation"])
        label=label_by_seq[sequence]

        active_slots=set(verifier.active_slots)
        if operation in {"stop","restart"} and slot not in active_slots:
            raise RuntimeError(
                f"generator produced invalid {operation} for inactive {slot}"
            )
        if operation=="start" and slot in active_slots:
            raise RuntimeError(
                f"generator produced invalid start for active {slot}"
            )

        pre_profiles=copy.deepcopy(profiles)
        pre_witnesses=copy.deepcopy(witnesses)
        verifier.begin_transition(operation,slot)

        observed=[
            copy.deepcopy(row)
            for row in pre_profiles
            if row["slot"]!=slot
        ]
        observed_witness={
            key_:copy.deepcopy(value)
            for key_,value in pre_witnesses.items()
            if key_!=slot
        }
        if label["attacked"]:
            target=str(label["target_slot"])
            observed=mutate(observed,target,str(label["family"]))

        relational_alerts=verifier.verify(
            observed,observed_witness
        )
        signed_full_no_witness=signed_full_policy_alert(
            policy,pre_profiles,observed,operation,slot,None
        )
        signed_full_with_witness=signed_full_policy_alert(
            policy,pre_profiles,observed,operation,slot,pre_witnesses
        )
        strict_snapshot_alert=(
            canonical_state(observed)!=canonical_state(pre_profiles)
        )
        count_alert=count_status_alert(pre_profiles,observed)

        verifier.end_transition()
        if operation=="stop":
            profiles=[
                row for row in profiles if row["slot"]!=slot
            ]
            witnesses.pop(slot,None)
        elif operation=="start":
            uid=next_uuid(slot,sequence)
            profiles.append(policy.expected_profile(slot,uid))
            p=policy.slots[slot]
            witnesses[slot]={
                "slot":slot,
                "nf_type":p["nf_type"],
                "endpoint":p["endpoint"],
                "nf_instance_id":uid,
                "process_alive":True,
                "direct_sbi_tcp_reachable":True,
            }
        elif operation=="restart":
            uid=next_uuid(slot,sequence)
            profiles=[
                row for row in profiles if row["slot"]!=slot
            ]
            profiles.append(policy.expected_profile(slot,uid))
            p=policy.slots[slot]
            witnesses[slot]={
                "slot":slot,
                "nf_type":p["nf_type"],
                "endpoint":p["endpoint"],
                "nf_instance_id":uid,
                "process_alive":True,
                "direct_sbi_tcp_reachable":True,
            }

        post_profiles=copy.deepcopy(profiles)
        pre_or_post_alert=(
            canonical_state(observed)!=canonical_state(pre_profiles)
            and canonical_state(observed)!=canonical_state(post_profiles)
        )
        if verifier.verify(profiles,witnesses):
            raise RuntimeError(
                f"post-transition clean state rejected at {sequence}"
            )

        decisions.append({
            "sequence":sequence,
            "event_id":event["event_id"],
            "alerts":{
                "relational_signed_event":bool(relational_alerts),
                "lifecycle_aware_full_policy_no_witness":
                    bool(signed_full_no_witness),
                "lifecycle_aware_full_policy_plus_witness":
                    bool(signed_full_with_witness),
                "full_pre_or_post_snapshot":pre_or_post_alert,
                "strict_pre_snapshot":strict_snapshot_alert,
                "count_status":count_alert,
            },
        })

    metrics=compute_metrics(decisions,labels)
    benign=sum(1 for row in labels if not row["attacked"])
    attacks=len(labels)-benign
    report={
        "stage":39,
        "kind":"external signed lifecycle and baseline evaluation",
        "events":len(events),
        "benign_events":benign,
        "attacked_events":attacks,
        "labels_not_passed_to_detector_api":True,
        "labels_joined_for_metrics_after_decisions":True,
        "signed_orchestrator":{
            "source_id":"external-orchestrator-generator",
            "hmac":"HMAC-SHA256",
            "policy_binding":True,
            "sequence_replay_rejected":True,
            "tamper_rejected":True,
            "events_verified":len(events),
        },
        "baselines":metrics,
        "authorization_latency_ms":{
            "samples":len(auth_latencies),
            "median":statistics.median(auth_latencies),
            "max":max(auth_latencies),
        },
        "interpretation":{
            "lifecycle_aware_full_policy_plus_witness_is_strong_baseline":True,
            "no_uniqueness_claim_when_equally_expressive_lifecycle_and_witness_policy_matches_relational_result":True,
            "future_post_reference_used_by_relational_signed_event":False,
        },
    }
    (args.output/"stage39_orchestration_report.json").write_text(
        json.dumps(report,indent=2,ensure_ascii=False)+"\n",
        encoding="utf-8",
    )
    (args.output/"stage39_orchestration_decisions.jsonl").write_text(
        "\n".join(json.dumps(row,sort_keys=True) for row in decisions)+"\n",
        encoding="utf-8",
    )
    (args.output/"stage39_orchestration_report.md").write_text(
        "# Stage39 signed orchestration / baselines\n\n"
        f"- Events: {len(events)} (benign {benign}, attacked {attacks})\n"
        f"- Signed events verified: {len(events)}/{len(events)}\n"
        f"- Tamper/replay rejected: true/true\n"
        + "\n".join(
            f"- {name}: TP={m['TP']} FN={m['FN']} "
            f"FP={m['FP']} TN={m['TN']}"
            for name,m in metrics.items()
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report,indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
