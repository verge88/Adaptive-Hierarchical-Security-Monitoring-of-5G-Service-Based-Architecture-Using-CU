from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

WITNESS_DIR=Path("/run/stage39/witness")
SLOTS={
    "nrf1":("NRF","127.0.0.10","nrf.yaml"),
    "scp1":("SCP","127.0.0.11","scp.yaml"),
    "nssf1":("NSSF","127.0.0.12","nssf1.yaml"),
    "nssf2":("NSSF","127.0.0.13","nssf2.yaml"),
    "ausf1":("AUSF","127.0.0.14","ausf1.yaml"),
    "ausf2":("AUSF","127.0.0.15","ausf2.yaml"),
    "bsf1":("BSF","127.0.0.16","bsf1.yaml"),
    "bsf2":("BSF","127.0.0.17","bsf2.yaml"),
    "udm1":("UDM","127.0.0.18","udm1.yaml"),
    "udm2":("UDM","127.0.0.19","udm2.yaml"),
    "amf1":("AMF","127.0.0.20","amf1.yaml"),
    "smf1":("SMF","127.0.0.21","smf1.yaml"),
    "pcf1":("PCF","127.0.0.22","pcf1.yaml"),
}
CONFIG_TO_SLOT={config:slot for slot,(_,_,config) in SLOTS.items()}


def canonical_bytes(value):
    return json.dumps(
        value,sort_keys=True,separators=(",",":"),ensure_ascii=False
    ).encode()


def tcp_reachable(host,port=80):
    try:
        with socket.create_connection((host,port),timeout=0.5):
            return True
    except OSError:
        return False


def cmdline(pid):
    try:
        raw=Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return []
    return [
        part.decode(errors="replace")
        for part in raw.split(b"\0")
        if part
    ]


def config_from_cmdline(parts):
    for index,value in enumerate(parts[:-1]):
        if value=="-c":
            return Path(parts[index+1]).name
    return None


def collect():
    records={}
    for path in WITNESS_DIR.glob("*.tsv"):
        try:
            pid_s,nf_enum,nf_uuid=path.read_text().strip().split("\t")
            pid=int(pid_s)
        except Exception:
            continue
        parts=cmdline(pid)
        if not parts:
            continue
        config=config_from_cmdline(parts)
        slot=CONFIG_TO_SLOT.get(config)
        if slot is None:
            continue
        nf_type,endpoint,expected_config=SLOTS[slot]
        records[slot]={
            "slot":slot,
            "nf_type":nf_type,
            "endpoint":endpoint,
            "nf_instance_id":nf_uuid.lower(),
            "pid":pid,
            "nf_enum":int(nf_enum),
            "binary":Path(parts[0]).name,
            "config":expected_config,
            "process_alive":True,
            "direct_sbi_tcp_reachable":tcp_reachable(endpoint),
        }
    return records


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--private-key",type=Path,required=True)
    ap.add_argument("--challenge",type=Path,required=True)
    ap.add_argument("--timeout-seconds",type=float,default=45)
    args=ap.parse_args()

    challenge=args.challenge.read_text().strip()
    if not challenge:
        raise SystemExit("empty external witness challenge")

    private_key=serialization.load_pem_private_key(
        args.private_key.read_bytes(),password=None
    )
    if not isinstance(private_key,ec.EllipticCurvePrivateKey):
        raise SystemExit("external witness key must be EC")
    public_pem=private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_sha=hashlib.sha256(public_pem).hexdigest()

    deadline=time.time()+args.timeout_seconds
    records={}
    while time.time()<deadline:
        records=collect()
        if (
            set(records)==set(SLOTS)
            and all(
                row["process_alive"]
                and row["direct_sbi_tcp_reachable"]
                for row in records.values()
            )
        ):
            break
        time.sleep(0.1)
    if set(records)!=set(SLOTS):
        raise SystemExit(
            "external witness missing slots: "
            + ",".join(sorted(set(SLOTS)-set(records)))
        )
    unavailable=[
        slot for slot,row in records.items()
        if not (
            row["process_alive"]
            and row["direct_sbi_tcp_reachable"]
        )
    ]
    if unavailable:
        raise SystemExit(
            "external witness unreachable slots: "
            + ",".join(sorted(unavailable))
        )

    snapshot={
        "stage":39,
        "schema":"stage39-external-sidecar-witness-v1",
        "challenge":challenge,
        "issued_at_unix_ns":time.time_ns(),
        "nrf_discovery_used":False,
        "source":"separate-container:/proc+direct-sbi+runtime-uuid-record",
        "slots":{slot:records[slot] for slot in sorted(records)},
        "public_key_sha256":public_sha,
    }
    signature=private_key.sign(
        canonical_bytes(snapshot),ec.ECDSA(hashes.SHA256())
    )
    bundle={
        "snapshot":snapshot,
        "signature_base64":base64.b64encode(signature).decode(),
    }
    args.output.parent.mkdir(parents=True,exist_ok=True)
    tmp=args.output.with_suffix(args.output.suffix+".tmp")
    tmp.write_text(
        json.dumps(bundle,sort_keys=True,indent=2)+"\n",
        encoding="utf-8",
    )
    tmp.replace(args.output)
    print(json.dumps({
        "external_witness_slots":len(records),
        "public_key_sha256":public_sha,
        "output":str(args.output),
    },indent=2))


if __name__=="__main__":
    main()
