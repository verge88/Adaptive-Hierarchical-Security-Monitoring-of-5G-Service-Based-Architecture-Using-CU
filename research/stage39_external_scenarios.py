from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import random
import secrets
import time
from pathlib import Path


def canonical_bytes(value):
    return json.dumps(
        value,sort_keys=True,separators=(",",":"),ensure_ascii=False
    ).encode()


def sign(key,payload):
    return hmac.new(key,canonical_bytes(payload),hashlib.sha256).hexdigest()


def atomic_write(path,text):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+".tmp")
    tmp.write_text(text,encoding="utf-8")
    tmp.replace(path)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--policy",type=Path,required=True)
    ap.add_argument("--events",type=Path,required=True)
    ap.add_argument("--labels",type=Path,required=True)
    ap.add_argument("--key-hex",required=True)
    ap.add_argument("--seed",required=True)
    ap.add_argument("--count",type=int,default=5000)
    ap.add_argument("--attack-rate",type=float,default=0.30)
    args=ap.parse_args()

    policy=json.loads(args.policy.read_text(encoding="utf-8"))
    slots=sorted(policy["slots"])
    policy_digest=hashlib.sha256(
        canonical_bytes(policy)
    ).hexdigest()
    key=bytes.fromhex(args.key_hex)
    seed_int=int.from_bytes(
        hashlib.sha256(args.seed.encode()).digest()[:8],"big"
    )
    rng=random.Random(seed_int)
    active=set(slots)
    operations={"restart":0,"stop":0,"start":0}
    families=("identity","endpoint","service","fqdn","type","compound","duplicate")
    event_lines=[]
    label_lines=[]
    now_ms=int(time.time()*1000)

    for sequence in range(1,args.count+1):
        inactive=sorted(set(slots)-active)
        if inactive and rng.random()<0.38:
            operation="start"
            slot=rng.choice(inactive)
        else:
            slot=rng.choice(sorted(active))
            operation="restart" if rng.random()<0.72 else "stop"
        operations[operation]+=1
        payload={
            "schema":"stage39-lifecycle-intent-v1",
            "source_id":"external-orchestrator-generator",
            "sequence":sequence,
            "event_id":hashlib.sha256(
                f"{args.seed}:{sequence}:{slot}:{operation}".encode()
            ).hexdigest()[:24],
            "issued_at_ms":now_ms+sequence,
            "nonce":hashlib.sha256(
                f"nonce:{args.seed}:{sequence}".encode()
            ).hexdigest()[:32],
            "operation":operation,
            "slot":slot,
            "policy_sha256":policy_digest,
            "max_window_ms":5000,
        }
        envelope={
            "payload":payload,
            "hmac_sha256":sign(key,payload),
        }
        event_lines.append(json.dumps(envelope,sort_keys=True))

        attacked=rng.random()<args.attack_rate
        family=rng.choice(families) if attacked else None
        stable_candidates=sorted(active-{slot})
        target=(
            rng.choice(stable_candidates)
            if attacked and stable_candidates
            else None
        )
        if attacked and target is None:
            attacked=False
            family=None
        label_lines.append(json.dumps({
            "sequence":sequence,
            "attacked":attacked,
            "family":family,
            "target_slot":target,
        },sort_keys=True))

        if operation=="stop":
            active.remove(slot)
        elif operation=="start":
            active.add(slot)

    atomic_write(args.events,"\n".join(event_lines)+"\n")
    atomic_write(args.labels,"\n".join(label_lines)+"\n")
    summary={
        "schema":"stage39-external-generator-summary-v1",
        "seed_sha256":hashlib.sha256(args.seed.encode()).hexdigest(),
        "count":args.count,
        "attack_rate_requested":args.attack_rate,
        "operations":operations,
        "policy_sha256":policy_digest,
        "labels_separate_from_signed_event_stream":True,
    }
    atomic_write(
        args.events.with_suffix(".summary.json"),
        json.dumps(summary,indent=2,sort_keys=True)+"\n",
    )
    print(json.dumps(summary,indent=2))


if __name__=="__main__":
    main()
