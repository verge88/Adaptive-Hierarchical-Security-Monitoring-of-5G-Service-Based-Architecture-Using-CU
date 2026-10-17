from __future__ import annotations

import argparse
import asyncio
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

from stage39_kie import FreshnessAnchor, KIERequest, KIEResponse, sha256_json

ROOT=Path("/opt/stage39")
LOG=Path("/var/log/open5gs")
WITNESS=Path("/run/stage39/witness")
MUTATION_ROOT=Path("/run/stage38")
MUTATION_PLAN=MUTATION_ROOT/"plan.tsv"
MUTATION_ENABLE=MUTATION_ROOT/"enabled"
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
    "AMF":1,"SMF":1,"PCF":1,"SCP":1,
}
REQUESTER={
    "NSSF":"AMF","AUSF":"AMF","BSF":"PCF","UDM":"AMF",
    "AMF":"SMF","SMF":"AMF","PCF":"SMF","SCP":"AMF",
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
}
MUTATION_KINDS=(
    "identity_replacement",
    "endpoint_substitution",
    "service_injection",
    "fqdn_substitution",
    "nf_type_substitution",
    "compound_identity_service",
)


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


async def h2_get(host,port,path,timeout=5):
    reader,writer=await asyncio.open_connection(host,port)
    conn=H2Connection(H2Configuration(client_side=True,header_encoding="utf-8"))
    body=bytearray()
    status=None
    try:
        conn.initiate_connection()
        stream=conn.get_next_available_stream_id()
        conn.send_headers(stream,[
            (":method","GET"),
            (":scheme","http"),
            (":authority",f"{host}:{port}"),
            (":path",path),
            ("accept","application/json"),
            ("user-agent","stage39-live-probe"),
        ],end_stream=True)
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
                    body.extend(event.data)
                    conn.acknowledge_received_data(
                        event.flow_controlled_length,event.stream_id
                    )
                elif isinstance(event,StreamReset) and event.stream_id==stream:
                    raise RuntimeError("HTTP/2 stream reset")
                elif isinstance(event,StreamEnded) and event.stream_id==stream:
                    return status,bytes(body)
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


async def discover(nf_type):
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
    return rows


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
    for typ in EXPECTED_DISCOVERY:
        _,slot_code=MUTATION_TARGET_SLOT[typ]
        for tick,kind in enumerate(MUTATION_KINDS):
            variant=(tick%4)+1
            lines.append(f"{typ}\t{tick}\t{kind}\t{slot_code*100+variant}")
    MUTATION_PLAN.write_text("\n".join(lines)+"\n")
    MUTATION_ENABLE.touch()


async def clean_discovery_snapshot():
    result={}
    for typ,count in EXPECTED_DISCOVERY.items():
        rows=await discover(typ)
        if len(rows)!=count:
            raise RuntimeError(
                f"clean discovery count mismatch {typ}: {len(rows)} != {count}"
            )
        result[typ]=rows
    return result


async def run_native_mutations(clean):
    write_mutation_plan()
    matrix={}
    latencies=[]
    try:
        for typ in EXPECTED_DISCOVERY:
            slot,_=MUTATION_TARGET_SLOT[typ]
            endpoint=PROCESSES[slot][3]
            matrix[typ]={}
            for kind in MUTATION_KINDS:
                started=time.perf_counter_ns()
                rows=await discover(typ)
                changed=discovery_digest(rows)!=discovery_digest(clean[typ])
                if not changed:
                    raise RuntimeError(
                        f"native mutation not observed: {typ}/{kind}"
                    )
                validate_family_change(kind,clean[typ],rows,endpoint)
                elapsed=(time.perf_counter_ns()-started)/1_000_000
                matrix[typ][kind]={
                    "detected":True,
                    "discovery_request_to_detection_ms":elapsed,
                }
                latencies.append(elapsed)
    finally:
        MUTATION_ENABLE.unlink(missing_ok=True)

    restored=await clean_discovery_snapshot()
    restored_equal={
        typ:discovery_digest(restored[typ])==discovery_digest(clean[typ])
        for typ in EXPECTED_DISCOVERY
    }
    if not all(restored_equal.values()):
        raise RuntimeError(f"clean discovery did not restore: {restored_equal}")

    nrf_log=LOG/"nrf.log"
    text=nrf_log.read_text(errors="replace") if nrf_log.exists() else ""
    marker_count=text.count("STAGE39_NATIVE_NRF_MULTI_NF_MUTATION")
    expected=len(EXPECTED_DISCOVERY)*len(MUTATION_KINDS)
    if marker_count!=expected:
        raise RuntimeError(
            f"native mutation marker mismatch {marker_count} != {expected}"
        )

    return {
        "cases":expected,
        "detected":expected,
        "types":list(EXPECTED_DISCOVERY),
        "families":list(MUTATION_KINDS),
        "matrix":matrix,
        "clean_restored_after_hook":restored_equal,
        "native_marker_count":marker_count,
        "timing_ms":{
            "measurement_scope":
                "local NRF discovery request start through mutation validation; "
                "not attack-onset-to-alert latency",
            "sample_count":len(latencies),
            "median":statistics.median(latencies),
            "p95_nearest_rank":nearest_rank(latencies,0.95),
            "max":max(latencies),
        },
    }


async def main_async(output):
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

        native_mutations=await run_native_mutations(clean)

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
            (ROOT/"full_profile_policy.json").read_bytes()
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
            "native_mutations":{
                "cases":native_mutations["cases"],
                "detected":native_mutations["detected"],
                "types":native_mutations["types"],
                "families":native_mutations["families"],
                "native_marker_count":
                    native_mutations["native_marker_count"],
                "clean_restored_after_hook":
                    native_mutations["clean_restored_after_hook"],
                "timing_ms":native_mutations["timing_ms"],
            },
            "kie_bound_to_live_evidence":True,
            "telemetry_digest":telemetry_digest,
            "limitations":[
                "Native mutations alter serialized NRF discovery responses, "
                "not the persistent NRF registration database.",
                "NRF is controlled as a live process but is not mutated as a "
                "self-discovered NRF profile.",
                "Timing starts at the local discovery request, not at a "
                "separately timestamped adversarial action.",
                "mTLS/OAuth2 and SEPP-like checks remain in the separate "
                "Stage39 transport probe and are not 3GPP conformance tests.",
            ],
        }
        (output/"live_open5gs_report.json").write_text(
            json.dumps(report,indent=2,ensure_ascii=False)+"\n"
        )
        (output/"live_open5gs_evidence.json").write_text(
            json.dumps(live_evidence,indent=2,ensure_ascii=False)+"\n"
        )
        timing=report["native_mutations"]["timing_ms"]
        (output/"live_open5gs_report.md").write_text(
            "# Stage39 live Open5GS native validation\n\n"
            f"- Live processes: {report['live_processes']}\n"
            f"- Controlled NF types: "
            f"{', '.join(report['controlled_nf_types'])}\n"
            f"- Registered/discovered profile counts: "
            f"{report['registered_profile_observed']}\n"
            f"- Runtime witness records: "
            f"{report['runtime_witness_records']}\n"
            f"- Native response mutations: "
            f"{native_mutations['detected']}/{native_mutations['cases']}\n"
            f"- Mutation marker count: "
            f"{native_mutations['native_marker_count']}\n"
            f"- Clean discovery restored after hook: "
            f"{all(native_mutations['clean_restored_after_hook'].values())}\n"
            f"- Discovery-request-to-detection median / p95 / max: "
            f"{timing['median']:.3f} / "
            f"{timing['p95_nearest_rank']:.3f} / "
            f"{timing['max']:.3f} ms\n"
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
    args=ap.parse_args()
    asyncio.run(main_async(args.output))


if __name__=="__main__":
    main()
