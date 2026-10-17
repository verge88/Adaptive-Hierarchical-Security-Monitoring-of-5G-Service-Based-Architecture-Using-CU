from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import hashlib
import json
import math
import os
import signal
import socket
import statistics
import subprocess
import time
from pathlib import Path
from urllib.parse import urlencode

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from stage39_kie import FreshnessAnchor, KIERequest, KIEResponse, sha256_json

ROOT=Path("/opt/stage39")
LOG=Path("/var/log/open5gs")
WITNESS=Path("/run/stage39/witness")
MUTATION_ROOT=Path("/run/stage38")
MUTATION_PLAN=MUTATION_ROOT/"plan.tsv"
MUTATION_ENABLE=MUTATION_ROOT/"enabled"
LIVE_POLICY_PATH=ROOT/"live_policy.json"
NRF_HOST="127.0.0.10"
NRF_PORT=80

PROCESSES={
    "nrf1":("/src/open5gs/build/src/nrf/open5gs-nrfd","nrf.yaml","NRF","127.0.0.10"),
    "scp1":("/src/open5gs/build/src/scp/open5gs-scpd","scp.yaml","SCP","127.0.0.11"),
    "nssf1":("/src/open5gs/build/src/nssf/open5gs-nssfd","nssf1.yaml","NSSF","127.0.0.12"),
    "nssf2":("/src/open5gs/build/src/nssf/open5gs-nssfd","nssf2.yaml","NSSF","127.0.0.13"),
    "ausf1":("/src/open5gs/build/src/ausf/open5gs-ausfd","ausf1.yaml","AUSF","127.0.0.14"),
    "ausf2":("/src/open5gs/build/src/ausf/open5gs-ausfd","ausf2.yaml","AUSF","127.0.0.15"),
    "bsf1":("/src/open5gs/build/src/bsf/open5gs-bsfd","bsf1.yaml","BSF","127.0.0.16"),
    "bsf2":("/src/open5gs/build/src/bsf/open5gs-bsfd","bsf2.yaml","BSF","127.0.0.17"),
    "udm1":("/src/open5gs/build/src/udm/open5gs-udmd","udm1.yaml","UDM","127.0.0.18"),
    "udm2":("/src/open5gs/build/src/udm/open5gs-udmd","udm2.yaml","UDM","127.0.0.19"),
    "amf1":("/src/open5gs/build/src/amf/open5gs-amfd","amf1.yaml","AMF","127.0.0.20"),
    "smf1":("/src/open5gs/build/src/smf/open5gs-smfd","smf1.yaml","SMF","127.0.0.21"),
    "pcf1":("/src/open5gs/build/src/pcf/open5gs-pcfd","pcf1.yaml","PCF","127.0.0.22"),
}

EXPECTED_DISCOVERY={
    "NSSF":2,"AUSF":2,"BSF":2,"UDM":2,
    "AMF":1,"SMF":1,"PCF":1,"SCP":1,"NRF":1,
}
REQUESTER={
    "NSSF":"AMF","AUSF":"AMF","BSF":"PCF","UDM":"AMF",
    "AMF":"SMF","SMF":"AMF","PCF":"SMF","SCP":"AMF","NRF":"AMF",
}
MUTATION_TARGET_SLOT={
    "NSSF":("nssf1",1),
    "AUSF":("ausf1",3),
    "BSF":("bsf1",5),
    "UDM":("udm1",7),
    "AMF":("amf1",9),
    "SMF":("smf1",10),
    "PCF":("pcf1",11),
    "SCP":("scp1",12),
    "NRF":("nrf1",13),
}
MUTATION_KINDS=(
    "identity_replacement",
    "endpoint_substitution",
    "service_injection",
    "fqdn_substitution",
    "nf_type_substitution",
    "compound_identity_service",
)
BOUNDARY_MUTATION_KINDS=("duplicate_profile",)


def mutation_cases():
    cases=[]
    for kind in MUTATION_KINDS:
        for variant in range(1,5):
            cases.append({
                "kind":kind,
                "variant":variant,
                "article_family":True,
            })
    for kind in BOUNDARY_MUTATION_KINDS:
        cases.append({
            "kind":kind,
            "variant":1,
            "article_family":False,
        })
    return cases


def tcp_ready(host,port=80,timeout=0.3):
    try:
        with socket.create_connection((host,port),timeout=timeout):
            return True
    except OSError:
        return False


def wait_tcp(host,port=80,seconds=15):
    deadline=time.time()+seconds
    while time.time()<deadline:
        if tcp_ready(host,port):
            return
        time.sleep(0.1)
    raise RuntimeError(f"TCP not ready {host}:{port}")


async def h2_request(method,host,port,path,body=None,timeout=5):
    reader,writer=await asyncio.open_connection(host,port)
    conn=H2Connection(H2Configuration(client_side=True,header_encoding="utf-8"))
    response_body=bytearray()
    status=None
    payload=None if body is None else (
        body if isinstance(body,bytes)
        else json.dumps(body,separators=(",",":")).encode()
    )
    try:
        conn.initiate_connection()
        stream=conn.get_next_available_stream_id()
        headers=[
            (":method",method),
            (":scheme","http"),
            (":authority",f"{host}:{port}"),
            (":path",path),
            ("accept","application/json"),
            ("user-agent","stage39-live-probe"),
        ]
        if payload is not None:
            headers.extend([
                ("content-type","application/json"),
                ("content-length",str(len(payload))),
            ])
        conn.send_headers(stream,headers,end_stream=payload is None)
        if payload is not None:
            conn.send_data(stream,payload,end_stream=True)
        writer.write(conn.data_to_send())
        await writer.drain()
        while True:
            chunk=await asyncio.wait_for(reader.read(65535),timeout)
            if not chunk:
                raise RuntimeError("HTTP/2 peer closed early")
            for event in conn.receive_data(chunk):
                if isinstance(event,ResponseReceived) and event.stream_id==stream:
                    status=int(dict(event.headers)[":status"])
                elif isinstance(event,DataReceived) and event.stream_id==stream:
                    response_body.extend(event.data)
                    conn.acknowledge_received_data(
                        event.flow_controlled_length,event.stream_id
                    )
                elif isinstance(event,StreamReset) and event.stream_id==stream:
                    raise RuntimeError("HTTP/2 stream reset")
                elif isinstance(event,StreamEnded) and event.stream_id==stream:
                    return status,bytes(response_body)
            outbound=conn.data_to_send()
            if outbound:
                writer.write(outbound)
                await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def h2_get(host,port,path,timeout=5):
    return await h2_request("GET",host,port,path,timeout=timeout)

async def discover_document(nf_type):
    query=urlencode({
        "target-nf-type":nf_type,
        "requester-nf-type":REQUESTER[nf_type],
    })
    status,body=await h2_get(
        NRF_HOST,NRF_PORT,f"/nnrf-disc/v1/nf-instances?{query}"
    )
    if status!=200:
        raise RuntimeError(
            f"discovery {nf_type} status {status}: {body[:500]!r}"
        )
    doc=json.loads(body)
    rows=doc.get("nfInstances")
    if not isinstance(rows,list):
        raise RuntimeError(f"discovery {nf_type} missing nfInstances")
    return doc


async def discover(nf_type):
    return (await discover_document(nf_type))["nfInstances"]


def load_live_policy():
    doc=json.loads(LIVE_POLICY_PATH.read_text())
    if int(doc.get("version",0))!=1 or not isinstance(doc.get("slots"),dict):
        raise RuntimeError("invalid live policy")
    return doc


def profile_service_names(row):
    return sorted(
        str(s.get("serviceName",""))
        for s in row.get("nfServices",[])
        if isinstance(s,dict)
    )


def live_policy_alerts(nf_type,rows,witness,policy,include_witness=True):
    expected_slots={
        slot:item
        for slot,item in policy["slots"].items()
        if item["nf_type"]==nf_type
    }
    alerts=[]
    ids=[
        str(row.get("nfInstanceId","")).lower()
        for row in rows
        if isinstance(row,dict)
    ]
    if len(ids)!=len(set(ids)):
        alerts.append(f"duplicate_nfInstanceId:{nf_type}")
    assigned=set()
    assigned_counts={}
    for row in rows:
        addresses=row.get("ipv4Addresses")
        addresses=addresses if isinstance(addresses,list) else []
        candidates=[
            slot for slot,item in expected_slots.items()
            if item["endpoint"] in addresses
        ]
        if len(candidates)!=1:
            alerts.append(
                f"unassigned_or_ambiguous_endpoint:{nf_type}:"
                f"{','.join(str(x) for x in addresses)}"
            )
            continue
        slot=candidates[0]
        assigned.add(slot)
        assigned_counts[slot]=assigned_counts.get(slot,0)+1
        expected=expected_slots[slot]
        if row.get("nfType")!=expected["nf_type"]:
            alerts.append(f"nf_type:{slot}")
        if sorted(str(x) for x in addresses)!=[expected["endpoint"]]:
            alerts.append(f"endpoint:{slot}")
        if str(row.get("fqdn") or "")!=str(expected.get("fqdn") or ""):
            alerts.append(f"fqdn:{slot}")
        expected_services=expected.get("service_names")
        if expected_services is not None:
            if profile_service_names(row)!=sorted(expected_services):
                alerts.append(f"services:{slot}")
        if include_witness:
            w=witness.get(slot)
            if not isinstance(w,dict):
                alerts.append(f"witness_missing:{slot}")
            else:
                if str(row.get("nfInstanceId","")).lower()!=str(
                    w.get("nf_instance_id","")
                ).lower():
                    alerts.append(f"witness_uuid:{slot}")
                if w.get("nf_type")!=expected["nf_type"]:
                    alerts.append(f"witness_type:{slot}")
                if w.get("endpoint")!=expected["endpoint"]:
                    alerts.append(f"witness_endpoint:{slot}")
                if w.get("process_alive") is not True:
                    alerts.append(f"witness_process:{slot}")
                if w.get("tcp_reachable") is not True:
                    alerts.append(f"witness_reachability:{slot}")
    for slot,count in assigned_counts.items():
        if count>1:
            alerts.append(f"ambiguous_slot:{slot}")
    missing=sorted(set(expected_slots)-assigned)
    alerts.extend(f"missing_slot:{slot}" for slot in missing)
    return sorted(set(alerts))



def live_witness_only_alerts(nf_type,rows,witness):
    expected={
        slot:row for slot,row in witness.items()
        if row.get("nf_type")==nf_type
    }
    alerts=[]
    ids=[
        str(row.get("nfInstanceId","")).lower()
        for row in rows if isinstance(row,dict)
    ]
    if len(ids)!=len(set(ids)):
        alerts.append(f"witness_duplicate_nfInstanceId:{nf_type}")
    assigned=set()
    counts={}
    for row in rows:
        addresses=row.get("ipv4Addresses")
        addresses=addresses if isinstance(addresses,list) else []
        candidates=[
            slot for slot,w in expected.items()
            if w.get("endpoint") in addresses
        ]
        if len(candidates)!=1:
            alerts.append(
                f"witness_unassigned_or_ambiguous_endpoint:{nf_type}:"
                f"{','.join(str(x) for x in addresses)}"
            )
            continue
        slot=candidates[0]
        assigned.add(slot)
        counts[slot]=counts.get(slot,0)+1
        w=expected[slot]
        if str(row.get("nfInstanceId","")).lower()!=str(
            w.get("nf_instance_id","")
        ).lower():
            alerts.append(f"witness_uuid:{slot}")
        if row.get("nfType")!=w.get("nf_type"):
            alerts.append(f"witness_type:{slot}")
        if w.get("process_alive") is not True:
            alerts.append(f"witness_process:{slot}")
        if w.get("tcp_reachable") is not True:
            alerts.append(f"witness_reachability:{slot}")
    for slot,count in counts.items():
        if count>1:
            alerts.append(f"witness_ambiguous_slot:{slot}")
    for slot in sorted(set(expected)-assigned):
        alerts.append(f"witness_missing_slot:{slot}")
    return sorted(set(alerts))


def validate_all_live_policy(discovery,witness,policy):
    alerts={}
    for typ,rows in discovery.items():
        found=live_policy_alerts(typ,rows,witness,policy)
        if found:
            alerts[typ]=found
    nrf=policy["slots"]["nrf1"]
    nrf_w=witness.get("nrf1")
    if not isinstance(nrf_w,dict):
        alerts.setdefault("NRF",[]).append("witness_missing:nrf1")
    else:
        if nrf_w.get("nf_type")!=nrf["nf_type"]:
            alerts.setdefault("NRF",[]).append("witness_type:nrf1")
        if nrf_w.get("endpoint")!=nrf["endpoint"]:
            alerts.setdefault("NRF",[]).append("witness_endpoint:nrf1")
        if nrf_w.get("process_alive") is not True:
            alerts.setdefault("NRF",[]).append("witness_process:nrf1")
        if nrf_w.get("tcp_reachable") is not True:
            alerts.setdefault("NRF",[]).append("witness_reachability:nrf1")
    return alerts


def canonical_bytes(value):
    return json.dumps(
        value,sort_keys=True,separators=(",",":"),ensure_ascii=False
    ).encode()


def verify_external_witness_bundle(bundle_path,public_key_path,challenge_path):
    bundle=json.loads(bundle_path.read_text())
    snapshot=bundle.get("snapshot")
    signature_b64=bundle.get("signature_base64")
    if not isinstance(snapshot,dict) or not isinstance(signature_b64,str):
        raise RuntimeError("invalid external witness bundle")
    public_pem=public_key_path.read_bytes()
    public_key=serialization.load_pem_public_key(public_pem)
    if not isinstance(public_key,ec.EllipticCurvePublicKey):
        raise RuntimeError("external witness public key must be EC")
    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            canonical_bytes(snapshot),
            ec.ECDSA(hashes.SHA256()),
        )
    except Exception as exc:
        raise RuntimeError("external witness signature invalid") from exc
    expected_sha=hashlib.sha256(public_pem).hexdigest()
    if snapshot.get("public_key_sha256")!=expected_sha:
        raise RuntimeError("external witness public key digest mismatch")
    challenge=challenge_path.read_text().strip()
    if snapshot.get("challenge")!=challenge:
        raise RuntimeError("external witness challenge mismatch")
    if int(snapshot.get("stage",-1))!=39:
        raise RuntimeError("external witness stage mismatch")
    if snapshot.get("nrf_discovery_used") is not False:
        raise RuntimeError("external witness unexpectedly used NRF discovery")
    issued=int(snapshot.get("issued_at_unix_ns",0))
    if issued<=0 or abs(time.time_ns()-issued)>120_000_000_000:
        raise RuntimeError("external witness stale")
    slots=snapshot.get("slots")
    if not isinstance(slots,dict) or set(slots)!=set(PROCESSES):
        raise RuntimeError(
            "external witness slot set mismatch: "
            f"{sorted(slots) if isinstance(slots,dict) else slots}"
        )
    normalized={}
    for slot,row in slots.items():
        expected_type=PROCESSES[slot][2]
        expected_endpoint=PROCESSES[slot][3]
        if row.get("nf_type")!=expected_type:
            raise RuntimeError(f"external witness type mismatch {slot}")
        if row.get("endpoint")!=expected_endpoint:
            raise RuntimeError(f"external witness endpoint mismatch {slot}")
        if row.get("process_alive") is not True:
            raise RuntimeError(f"external witness dead process {slot}")
        if row.get("direct_sbi_tcp_reachable") is not True:
            raise RuntimeError(f"external witness unreachable endpoint {slot}")
        normalized[slot]={
            **row,
            "tcp_reachable":row["direct_sbi_tcp_reachable"],
        }
    return normalized,{
        "snapshot":snapshot,
        "signature_base64":signature_b64,
        "verified":True,
        "public_key_sha256":expected_sha,
    }


def wait_external_witness(
    bundle_path,public_key_path,challenge_path,timeout_seconds=60
):
    deadline=time.time()+timeout_seconds
    last=None
    while time.time()<deadline:
        if bundle_path.exists():
            try:
                return verify_external_witness_bundle(
                    bundle_path,public_key_path,challenge_path
                )
            except Exception as exc:
                last=exc
        time.sleep(0.1)
    raise RuntimeError(
        f"external witness unavailable or invalid: {last}"
    )

def canonical_rows(rows):
    return sorted(
        rows,
        key=lambda row:(
            str(row.get("nfInstanceId","")),
            str(row.get("nfType","")),
            json.dumps(row,sort_keys=True,separators=(",",":")),
        ),
    )


def discovery_digest(rows):
    return sha256_json(canonical_rows(rows))


def row_with_endpoint(rows,endpoint):
    for row in rows:
        addresses=row.get("ipv4Addresses")
        if isinstance(addresses,list) and endpoint in addresses:
            return row
    raise RuntimeError(f"profile with endpoint {endpoint} not found")


def row_with_uuid(rows,nf_id):
    nf_id=str(nf_id).lower()
    for row in rows:
        if str(row.get("nfInstanceId","")).lower()==nf_id:
            return row
    raise RuntimeError(f"profile with UUID {nf_id} not found")


def validate_family_change(kind,clean_rows,mutated_rows,target_endpoint):
    clean=row_with_endpoint(clean_rows,target_endpoint)
    clean_uuid=str(clean.get("nfInstanceId","")).lower()
    if kind=="duplicate_profile":
        duplicates=[
            row for row in mutated_rows
            if str(row.get("nfInstanceId","")).lower()==clean_uuid
        ]
        if len(duplicates)<2:
            raise RuntimeError(
                "duplicate_profile did not duplicate the target profile"
            )
        return
    if kind in {"identity_replacement","compound_identity_service"}:
        mutated=row_with_endpoint(mutated_rows,target_endpoint)
    else:
        mutated=row_with_uuid(mutated_rows,clean_uuid)

    checks={
        "identity_replacement":
            str(mutated.get("nfInstanceId","")).lower()!=clean_uuid,
        "endpoint_substitution":
            mutated.get("ipv4Addresses")!=clean.get("ipv4Addresses"),
        "service_injection":
            mutated.get("nfServices")!=clean.get("nfServices"),
        "fqdn_substitution":
            mutated.get("fqdn")!=clean.get("fqdn"),
        "nf_type_substitution":
            mutated.get("nfType")!=clean.get("nfType"),
        "compound_identity_service":
            (
                str(mutated.get("nfInstanceId","")).lower()!=clean_uuid
                and mutated.get("nfServices")!=clean.get("nfServices")
            ),
    }
    if not checks[kind]:
        raise RuntimeError(f"mutation family {kind} did not change expected fields")


def nearest_rank(values,probability):
    ordered=sorted(values)
    if not ordered:
        raise ValueError("empty latency sample")
    return ordered[max(1,math.ceil(probability*len(ordered)))-1]


def process_cmdline(pid):
    raw=Path(f"/proc/{pid}/cmdline").read_bytes()
    return [x.decode(errors="replace") for x in raw.split(b"\0") if x]


def collect_witness(processes):
    records={}
    pid_to_slot={proc.pid:slot for slot,proc in processes.items()}
    for path in WITNESS.glob("*.tsv"):
        try:
            pid_s,nf_enum,nf_uuid=path.read_text().strip().split("\t")
            pid=int(pid_s)
        except Exception:
            continue
        slot=pid_to_slot.get(pid)
        if slot is None:
            continue
        _,_,typ,endpoint=PROCESSES[slot]
        records[slot]={
            "pid":pid,
            "nf_enum":int(nf_enum),
            "nf_instance_id":nf_uuid.lower(),
            "nf_type":typ,
            "endpoint":endpoint,
            "process_alive":processes[slot].poll() is None,
            "tcp_reachable":tcp_ready(endpoint),
            "cmdline":process_cmdline(pid),
        }
    return records


def log_tail(slot):
    path=LOG/f"stage39-{slot}-stdout.log"
    return path.read_text(errors="replace")[-4000:] if path.exists() else ""


def start(slot):
    binary,config,_,_=PROCESSES[slot]
    handle=open(LOG/f"stage39-{slot}-stdout.log","ab",buffering=0)
    return subprocess.Popen(
        [binary,"-c",str(ROOT/config)],
        stdout=handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env={**os.environ,"STAGE38_WITNESS_DIR":str(WITNESS)},
    )


def stop_all(processes):
    for proc in processes.values():
        if proc.poll() is None:
            try:
                os.killpg(proc.pid,signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline=time.time()+5
    while (
        time.time()<deadline
        and any(p.poll() is None for p in processes.values())
    ):
        time.sleep(0.05)
    for proc in processes.values():
        if proc.poll() is None:
            try:
                os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:
                pass


def write_mutation_plan():
    MUTATION_ROOT.mkdir(parents=True,exist_ok=True)
    lines=[]
    cases=mutation_cases()
    for typ in EXPECTED_DISCOVERY:
        _,slot_code=MUTATION_TARGET_SLOT[typ]
        for tick,case in enumerate(cases):
            lines.append(
                f"{typ}\t{tick}\t{case['kind']}\t"
                f"{slot_code*100+case['variant']}"
            )
    MUTATION_PLAN.write_text("\n".join(lines)+"\n")
    MUTATION_ENABLE.touch()


async def clean_discovery_snapshot(expected=None):
    expected=expected or EXPECTED_DISCOVERY
    result={}
    for typ,count in expected.items():
        rows=await discover(typ)
        if len(rows)!=count:
            raise RuntimeError(
                f"clean discovery count mismatch {typ}: {len(rows)} != {count}"
            )
        result[typ]=rows
    return result


async def run_native_mutations(clean,witness,policy):
    write_mutation_plan()
    cases=mutation_cases()
    matrix={}
    request_latencies=[]
    mutation_latencies=[]
    article_detected=0
    boundary_detected=0
    try:
        for typ in EXPECTED_DISCOVERY:
            slot,_=MUTATION_TARGET_SLOT[typ]
            endpoint=PROCESSES[slot][3]
            matrix[typ]={}
            for case in cases:
                kind=case["kind"]
                variant=case["variant"]
                label=f"{kind}:v{variant}"
                started=time.perf_counter_ns()
                doc=await discover_document(typ)
                rows=doc["nfInstances"]
                changed=discovery_digest(rows)!=discovery_digest(clean[typ])
                if not changed:
                    raise RuntimeError(
                        f"native mutation not observed: {typ}/{label}"
                    )
                validate_family_change(kind,clean[typ],rows,endpoint)
                policy_alerts=live_policy_alerts(
                    typ,rows,witness,policy
                )
                if not policy_alerts:
                    raise RuntimeError(
                        f"independent live policy missed {typ}/{label}"
                    )
                detected_ns=time.monotonic_ns()
                elapsed=(time.perf_counter_ns()-started)/1_000_000
                mutation_ns=doc.get("stage39MutationMonotonicNs")
                if not isinstance(mutation_ns,(int,float)):
                    raise RuntimeError(
                        f"missing mutation timestamp: {typ}/{label}"
                    )
                mutation_to_detection=(
                    detected_ns-int(mutation_ns)
                )/1_000_000
                if mutation_to_detection < 0:
                    raise RuntimeError(
                        f"negative mutation latency: {typ}/{label}"
                    )
                matrix[typ][label]={
                    "detected":True,
                    "kind":kind,
                    "variant":variant,
                    "article_family":case["article_family"],
                    "policy_alerts":policy_alerts,
                    "discovery_request_to_detection_ms":elapsed,
                    "mutation_to_detection_ms":mutation_to_detection,
                }
                if case["article_family"]:
                    article_detected+=1
                else:
                    boundary_detected+=1
                request_latencies.append(elapsed)
                mutation_latencies.append(mutation_to_detection)
    finally:
        MUTATION_ENABLE.unlink(missing_ok=True)

    restored=await clean_discovery_snapshot()
    restored_equal={
        typ:discovery_digest(restored[typ])==discovery_digest(clean[typ])
        for typ in EXPECTED_DISCOVERY
    }
    if not all(restored_equal.values()):
        raise RuntimeError(f"clean discovery did not restore: {restored_equal}")
    restored_policy_alerts=validate_all_live_policy(
        restored,witness,policy
    )
    if restored_policy_alerts:
        raise RuntimeError(
            f"restored discovery violates independent policy: "
            f"{restored_policy_alerts}"
        )

    nrf_log=LOG/"nrf.log"
    text=nrf_log.read_text(errors="replace") if nrf_log.exists() else ""
    marker_count=text.count("STAGE39_NATIVE_NRF_MULTI_NF_MUTATION")
    article_cases=(
        len(EXPECTED_DISCOVERY)*len(MUTATION_KINDS)*4
    )
    boundary_cases=(
        len(EXPECTED_DISCOVERY)*len(BOUNDARY_MUTATION_KINDS)
    )
    expected=article_cases+boundary_cases
    if marker_count!=expected:
        raise RuntimeError(
            f"native mutation marker mismatch {marker_count} != {expected}"
        )
    if article_detected!=article_cases:
        raise RuntimeError(
            f"native article mutation coverage "
            f"{article_detected} != {article_cases}"
        )
    if boundary_detected!=boundary_cases:
        raise RuntimeError(
            f"native boundary mutation coverage "
            f"{boundary_detected} != {boundary_cases}"
        )

    return {
        "cases":expected,
        "detected":expected,
        "article_cases":article_cases,
        "article_detected":article_detected,
        "boundary_cases":boundary_cases,
        "boundary_detected":boundary_detected,
        "types":list(EXPECTED_DISCOVERY),
        "article_families":list(MUTATION_KINDS),
        "boundary_families":list(BOUNDARY_MUTATION_KINDS),
        "variants_per_article_family":4,
        "matrix":matrix,
        "clean_restored_after_hook":restored_equal,
        "restored_policy_alerts":restored_policy_alerts,
        "native_marker_count":marker_count,
        "timing_ms":{
            "sample_count":len(request_latencies),
            "discovery_request_to_detection":{
                "scope":
                    "local discovery request start through independent-policy alert",
                "median":statistics.median(request_latencies),
                "p95_nearest_rank":nearest_rank(request_latencies,0.95),
                "max":max(request_latencies),
            },
            "mutation_application_to_detection":{
                "scope":
                    "CLOCK_MONOTONIC timestamp injected by NRF immediately "
                    "after profile mutation through independent-policy alert",
                "median":statistics.median(mutation_latencies),
                "p95_nearest_rank":nearest_rank(mutation_latencies,0.95),
                "max":max(mutation_latencies),
            },
        },
    }


def poison_registration_profile(clean_profile):
    fake=copy.deepcopy(clean_profile)
    fake_uuid="39000000-0000-4000-8000-000000000001"
    fake["nfInstanceId"]=fake_uuid
    fake["nfStatus"]="REGISTERED"
    fake["fqdn"]="poisoned-stage39.invalid"
    fake["ipv4Addresses"]=["203.0.113.250"]
    for index,service in enumerate(fake.get("nfServices",[]),1):
        if not isinstance(service,dict):
            continue
        service["serviceInstanceId"]=(
            f"39000000-0000-4000-8000-{index:012d}"
        )
        service["fqdn"]="poisoned-stage39.invalid"
        for endpoint in service.get("ipEndPoints",[]):
            if isinstance(endpoint,dict):
                endpoint["ipv4Address"]="203.0.113.250"
                endpoint["port"]=9380+index
        if "apiPrefix" in service:
            service["apiPrefix"]=f"http://203.0.113.250:{9380+index}"
    return fake_uuid,fake


async def run_persistent_registration_poisoning(clean,witness,policy):
    source=row_with_endpoint(clean["NSSF"],PROCESSES["nssf1"][3])
    fake_uuid,fake=poison_registration_profile(source)
    path=f"/nnrf-nfm/v1/nf-instances/{fake_uuid}"
    status,body=await h2_request(
        "PUT",NRF_HOST,NRF_PORT,path,body=fake,timeout=8
    )
    if status not in {200,201}:
        raise RuntimeError(
            f"persistent registration poison rejected unexpectedly "
            f"status={status} body={body[:1000]!r}"
        )
    try:
        rows=await discover("NSSF")
        fake_rows=[
            row for row in rows
            if str(row.get("nfInstanceId","")).lower()==fake_uuid
        ]
        if len(fake_rows)!=1:
            raise RuntimeError(
                f"poisoned registration not discoverable: "
                f"matches={len(fake_rows)}"
            )
        alerts=live_policy_alerts("NSSF",rows,witness,policy)
        if not alerts:
            raise RuntimeError(
                "independent live policy accepted persistent poison"
            )
        poison={
            "registration_status":status,
            "fake_nf_instance_id":fake_uuid,
            "discoverable_after_registration":True,
            "discovery_count_with_poison":len(rows),
            "independent_policy_rejected":True,
            "policy_alerts":alerts,
        }
    finally:
        delete_status,delete_body=await h2_request(
            "DELETE",NRF_HOST,NRF_PORT,path,timeout=8
        )
        if delete_status not in {200,204}:
            raise RuntimeError(
                f"poison cleanup failed status={delete_status} "
                f"body={delete_body[:1000]!r}"
            )

    deadline=time.time()+10
    restored=None
    while time.time()<deadline:
        rows=await discover("NSSF")
        if (
            len(rows)==EXPECTED_DISCOVERY["NSSF"]
            and all(
                str(row.get("nfInstanceId","")).lower()!=fake_uuid
                for row in rows
            )
        ):
            restored=rows
            break
        await asyncio.sleep(0.1)
    if restored is None:
        raise RuntimeError("persistent poison cleanup did not converge")
    restored_alerts=live_policy_alerts(
        "NSSF",restored,witness,policy
    )
    if restored_alerts:
        raise RuntimeError(
            f"clean NSSF state violates policy after poison cleanup: "
            f"{restored_alerts}"
        )
    poison["cleanup_status"]=delete_status
    poison["clean_state_restored"]=True
    return poison


async def main_async(
    output,external_witness=None,external_public_key=None,
    external_challenge=None
):
    output.mkdir(parents=True,exist_ok=True)
    LOG.mkdir(parents=True,exist_ok=True)
    WITNESS.mkdir(parents=True,exist_ok=True)
    MUTATION_ROOT.mkdir(parents=True,exist_ok=True)
    MUTATION_ENABLE.unlink(missing_ok=True)
    MUTATION_PLAN.unlink(missing_ok=True)
    for p in WITNESS.glob("*.tsv"):
        p.unlink()

    processes={}
    try:
        processes["nrf1"]=start("nrf1")
        wait_tcp("127.0.0.10")
        processes["scp1"]=start("scp1")
        wait_tcp("127.0.0.11")

        for slot in [s for s in PROCESSES if s not in {"nrf1","scp1"}]:
            processes[slot]=start(slot)
            time.sleep(0.12)

        for slot,(_,_,_,endpoint) in PROCESSES.items():
            try:
                wait_tcp(endpoint,seconds=20)
            except Exception as exc:
                raise RuntimeError(
                    f"{slot} endpoint failed: {exc}; log={log_tail(slot)}"
                )

        clean={}
        deadline=time.time()+30
        last={}
        while time.time()<deadline:
            try:
                clean=await clean_discovery_snapshot()
                break
            except Exception as exc:
                last={"error":f"{type(exc).__name__}: {exc}"}
                clean={}
            await asyncio.sleep(0.2)
        if not clean:
            tails={slot:log_tail(slot) for slot in PROCESSES}
            raise RuntimeError(
                f"NRF convergence failed: {last}; logs={tails}"
            )

        external_witness_evidence=None
        if external_witness is not None:
            if external_public_key is None or external_challenge is None:
                raise RuntimeError(
                    "external witness requires public key and challenge"
                )
            witness,external_witness_evidence=wait_external_witness(
                external_witness,external_public_key,external_challenge
            )
        else:
            witness={}
            deadline=time.time()+10
            while time.time()<deadline:
                witness=collect_witness(processes)
                if set(witness)==set(PROCESSES):
                    break
                await asyncio.sleep(0.1)
            missing=sorted(set(PROCESSES)-set(witness))
            if missing:
                tails={slot:log_tail(slot) for slot in missing}
                raise RuntimeError(
                    f"missing runtime witness for {missing}; logs={tails}"
                )

        live_policy=load_live_policy()
        clean_policy_alerts=validate_all_live_policy(
            clean,witness,live_policy
        )
        if clean_policy_alerts:
            raise RuntimeError(
                f"clean live state violates independent policy: "
                f"{clean_policy_alerts}"
            )

        persistent_poison=await run_persistent_registration_poisoning(
            clean,witness,live_policy
        )
        native_mutations=await run_native_mutations(
            clean,witness,live_policy
        )

        live_evidence={
            "open5gs_ref":"v2.7.6",
            "processes":{
                slot:{
                    "nf_type":PROCESSES[slot][2],
                    "endpoint":PROCESSES[slot][3],
                    "pid":proc.pid,
                    "alive":proc.poll() is None,
                }
                for slot,proc in processes.items()
            },
            "clean_discovery":{
                typ:[
                    {
                        "nfInstanceId":row.get("nfInstanceId"),
                        "nfType":row.get("nfType"),
                        "nfStatus":row.get("nfStatus"),
                        "ipv4Addresses":row.get("ipv4Addresses",[]),
                        "fqdn":row.get("fqdn"),
                        "service_names":[
                            s.get("serviceName")
                            for s in row.get("nfServices",[])
                            if isinstance(s,dict)
                        ],
                    }
                    for row in rows
                ]
                for typ,rows in clean.items()
            },
            "runtime_witness":witness,
            "external_witness_evidence":external_witness_evidence,
            "independent_live_policy":{
                "document":live_policy,
                "sha256":hashlib.sha256(
                    LIVE_POLICY_PATH.read_bytes()
                ).hexdigest(),
                "clean_policy_alerts":clean_policy_alerts,
            },
            "persistent_registration_poisoning":persistent_poison,
            "native_mutations":native_mutations,
        }

        telemetry_digest=sha256_json(live_evidence)
        controller_key=hashlib.sha256(
            b"stage39-live-controller"
        ).digest()
        subject_key=hashlib.sha256(
            b"stage39-live-subject"
        ).digest()
        policy_digest=hashlib.sha256(
            LIVE_POLICY_PATH.read_bytes()
        ).hexdigest()
        now=int(time.time()*1000)
        anchor=FreshnessAnchor(
            output/"live_anchor.json",
            output/"live_anchor_mirror.json",
            hashlib.sha256(b"live-anchor-seal").digest(),
        )
        req=KIERequest.create(
            "stage39-live-verifier",
            "open5gs-testbed",
            1,
            policy_digest,
            telemetry_digest,
            controller_key,
            now,
            "cafebabecafebabecafebabecafebabe",
        )
        req.verify(
            controller_key,anchor,policy_digest,telemetry_digest,now
        )
        response=KIEResponse.create(
            req,
            {
                "live_processes":len(processes),
                "registered_profile_types":sorted(clean),
                "registered_profiles":sum(len(v) for v in clean.values()),
                "runtime_witness_records":len(witness),
                "native_mutation_cases":native_mutations["cases"],
                "native_mutation_detected":native_mutations["detected"],
                "persistent_registration_poison_rejected":
                    persistent_poison["independent_policy_rejected"],
                "evidence_digest":telemetry_digest,
            },
            subject_key,
            now,
        )
        response.verify(subject_key,req,now)

        report={
            "stage":39,
            "kind":"live Open5GS v2.7.6 native mutation validation",
            "open5gs_ref":"v2.7.6",
            "live_processes":len(processes),
            "controlled_nf_types":
                sorted({row[2] for row in PROCESSES.values()}),
            "registered_profile_expected":EXPECTED_DISCOVERY,
            "registered_profile_observed":{
                k:len(v) for k,v in clean.items()
            },
            "runtime_witness_records":len(witness),
            "external_witness":{
                "used":external_witness_evidence is not None,
                "verified":
                    bool(external_witness_evidence and
                         external_witness_evidence.get("verified")),
                "source":
                    external_witness_evidence["snapshot"]["source"]
                    if external_witness_evidence else
                    "in-container-fallback",
                "public_key_sha256":
                    external_witness_evidence.get("public_key_sha256")
                    if external_witness_evidence else None,
            },
            "independent_live_policy":{
                "sha256":policy_digest,
                "clean_policy_alerts":clean_policy_alerts,
            },
            "persistent_registration_poisoning":persistent_poison,
            "native_mutations":{
                "cases":native_mutations["cases"],
                "detected":native_mutations["detected"],
                "article_cases":native_mutations["article_cases"],
                "article_detected":native_mutations["article_detected"],
                "boundary_cases":native_mutations["boundary_cases"],
                "boundary_detected":native_mutations["boundary_detected"],
                "types":native_mutations["types"],
                "article_families":
                    native_mutations["article_families"],
                "boundary_families":
                    native_mutations["boundary_families"],
                "variants_per_article_family":
                    native_mutations["variants_per_article_family"],
                "native_marker_count":
                    native_mutations["native_marker_count"],
                "clean_restored_after_hook":
                    native_mutations["clean_restored_after_hook"],
                "timing_ms":native_mutations["timing_ms"],
            },
            "kie_bound_to_live_evidence":True,
            "telemetry_digest":telemetry_digest,
            "limitations":[
                "External witness runs in a separate container and keeps its "
                "private key outside the Open5GS container, but both containers "
                "still share one GitHub runner/kernel.",
                "Persistent poisoning test uses an intentionally registered "
                "test profile and removes it after validation.",
                "NRF is included through its live self-profile returned by "
                "NRF discovery and is mutated by the same native response hook "
                "used for the other discoverable NF types.",
                "Mutation-to-detection timing begins at instrumentation inside "
                "the NRF response-mutation path; it is not an external "
                "attacker-onset timestamp.",
                "Live Open5GS mTLS is validated by a dedicated second "
                "pass in the same workflow; OAuth2 and SEPP-like checks remain "
                "separate and are not 3GPP conformance tests.",
            ],
        }
        (output/"live_open5gs_report.json").write_text(
            json.dumps(report,indent=2,ensure_ascii=False)+"\n"
        )
        (output/"live_open5gs_evidence.json").write_text(
            json.dumps(live_evidence,indent=2,ensure_ascii=False)+"\n"
        )
        timing=report["native_mutations"]["timing_ms"]
        mutation_timing=timing["mutation_application_to_detection"]
        request_timing=timing["discovery_request_to_detection"]
        (output/"live_open5gs_report.md").write_text(
            "# Stage39 live Open5GS native validation\n\n"
            f"- Live processes: {report['live_processes']}\n"
            f"- Controlled NF types: "
            f"{', '.join(report['controlled_nf_types'])}\n"
            f"- Registered/discovered profile counts: "
            f"{report['registered_profile_observed']}\n"
            f"- Runtime witness records: "
            f"{report['runtime_witness_records']}\n"
            f"- External sidecar witness used/verified: "
            f"{report['external_witness']['used']}/"
            f"{report['external_witness']['verified']}\n"
            f"- Independent live policy clean alerts: "
            f"{len(clean_policy_alerts)}\n"
            f"- Persistent registration poisoning rejected by policy: "
            f"{persistent_poison['independent_policy_rejected']}\n"
            f"- Native article mutation variants: "
            f"{native_mutations['article_detected']}/"
            f"{native_mutations['article_cases']}\n"
            f"- Native duplicate boundary cases: "
            f"{native_mutations['boundary_detected']}/"
            f"{native_mutations['boundary_cases']}\n"
            f"- Native total response mutations: "
            f"{native_mutations['detected']}/{native_mutations['cases']}\n"
            f"- Mutation marker count: "
            f"{native_mutations['native_marker_count']}\n"
            f"- Clean discovery restored after hook: "
            f"{all(native_mutations['clean_restored_after_hook'].values())}\n"
            f"- Discovery-request-to-detection median / p95 / max: "
            f"{request_timing['median']:.3f} / "
            f"{request_timing['p95_nearest_rank']:.3f} / "
            f"{request_timing['max']:.3f} ms\n"
            f"- NRF-mutation-to-detection median / p95 / max: "
            f"{mutation_timing['median']:.3f} / "
            f"{mutation_timing['p95_nearest_rank']:.3f} / "
            f"{mutation_timing['max']:.3f} ms\n"
            f"- KIE bound to live evidence: "
            f"{report['kie_bound_to_live_evidence']}\n"
        )
        print(json.dumps(report,indent=2,ensure_ascii=False))
    finally:
        MUTATION_ENABLE.unlink(missing_ok=True)
        stop_all(processes)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--external-witness",type=Path)
    ap.add_argument("--external-witness-public-key",type=Path)
    ap.add_argument("--external-witness-challenge",type=Path)
    args=ap.parse_args()
    asyncio.run(main_async(
        args.output,
        args.external_witness,
        args.external_witness_public_key,
        args.external_witness_challenge,
    ))


if __name__=="__main__":
    main()
