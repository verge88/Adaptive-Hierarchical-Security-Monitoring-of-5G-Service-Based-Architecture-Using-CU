from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urlencode

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset

from stage39_kie import (
    FreshnessAnchor,
    KIERequest,
    KIEResponse,
    canonical_bytes,
    sha256_json,
)

ROOT=Path("/opt/stage39")
LOG=Path("/var/log/open5gs")
WITNESS=Path("/run/stage39/witness")
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
EXPECTED_DISCOVERY={"NSSF":2,"AUSF":2,"BSF":2,"UDM":2,"AMF":1,"SMF":1,"PCF":1}
REQUESTER={"NSSF":"AMF","AUSF":"AMF","BSF":"PCF","UDM":"AMF","AMF":"SMF","SMF":"AMF","PCF":"SMF","SCP":"AMF"}


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
                    conn.acknowledge_received_data(event.flow_controlled_length,event.stream_id)
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
    query=urlencode({"target-nf-type":nf_type,"requester-nf-type":REQUESTER[nf_type]})
    status,body=await h2_get(NRF_HOST,NRF_PORT,f"/nnrf-disc/v1/nf-instances?{query}")
    if status!=200:
        raise RuntimeError(f"discovery {nf_type} status {status}: {body[:500]!r}")
    doc=json.loads(body)
    rows=doc.get("nfInstances")
    if not isinstance(rows,list):
        raise RuntimeError(f"discovery {nf_type} missing nfInstances")
    return rows


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
    proc=subprocess.Popen(
        [binary,"-c",str(ROOT/config)],
        stdout=handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env={**os.environ,"STAGE38_WITNESS_DIR":str(WITNESS)},
    )
    return proc


def stop_all(processes):
    for proc in processes.values():
        if proc.poll() is None:
            try:
                os.killpg(proc.pid,signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline=time.time()+5
    while time.time()<deadline and any(p.poll() is None for p in processes.values()):
        time.sleep(0.05)
    for proc in processes.values():
        if proc.poll() is None:
            try:
                os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:
                pass


async def main_async(output):
    output.mkdir(parents=True,exist_ok=True)
    LOG.mkdir(parents=True,exist_ok=True)
    WITNESS.mkdir(parents=True,exist_ok=True)
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
                raise RuntimeError(f"{slot} endpoint failed: {exc}; log={log_tail(slot)}")

        discovery={}
        deadline=time.time()+30
        last={}
        while time.time()<deadline:
            try:
                last={}
                ok=True
                for typ,count in EXPECTED_DISCOVERY.items():
                    rows=await discover(typ)
                    last[typ]=rows
                    if len(rows)!=count:
                        ok=False
                if ok:
                    discovery=last
                    break
            except Exception as exc:
                last={"error":f"{type(exc).__name__}: {exc}"}
            await asyncio.sleep(0.2)
        if not discovery:
            tails={slot:log_tail(slot) for slot in PROCESSES}
            raise RuntimeError(f"NRF convergence failed: {last}; logs={tails}")

        scp_rows=[]
        try:
            scp_rows=await discover("SCP")
        except Exception:
            scp_rows=[]

        witness={}
        deadline=time.time()+10
        while time.time()<deadline:
            witness=collect_witness(processes)
            if set(witness)==set(PROCESSES):
                break
            await asyncio.sleep(0.1)
        missing=sorted(set(PROCESSES)-set(witness))
        if missing:
            raise RuntimeError(f"missing runtime witness for {missing}; logs={{s:log_tail(s) for s in missing}}")

        live_evidence={
            "open5gs_ref":"v2.7.6",
            "processes":{
                slot:{
                    "nf_type":PROCESSES[slot][2],
                    "endpoint":PROCESSES[slot][3],
                    "pid":proc.pid,
                    "alive":proc.poll() is None,
                } for slot,proc in processes.items()
            },
            "discovery":{
                typ:[
                    {
                        "nfInstanceId":row.get("nfInstanceId"),
                        "nfType":row.get("nfType"),
                        "nfStatus":row.get("nfStatus"),
                        "ipv4Addresses":row.get("ipv4Addresses",[]),
                        "fqdn":row.get("fqdn"),
                        "service_names":[s.get("serviceName") for s in row.get("nfServices",[]) if isinstance(s,dict)],
                    } for row in rows
                ] for typ,rows in discovery.items()
            },
            "scp_discovery_count":len(scp_rows),
            "runtime_witness":witness,
        }

        telemetry_digest=sha256_json(live_evidence)
        controller_key=hashlib.sha256(b"stage39-live-controller").digest()
        subject_key=hashlib.sha256(b"stage39-live-subject").digest()
        policy_digest=hashlib.sha256((ROOT/"full_profile_policy.json").read_bytes()).hexdigest()
        now=int(time.time()*1000)
        anchor=FreshnessAnchor(output/"live_anchor.json",output/"live_anchor_mirror.json",hashlib.sha256(b"live-anchor-seal").digest())
        req=KIERequest.create(
            "stage39-live-verifier","open5gs-testbed",1,
            policy_digest,telemetry_digest,controller_key,now,
            "cafebabecafebabecafebabecafebabe",
        )
        req.verify(controller_key,anchor,policy_digest,telemetry_digest,now)
        response=KIEResponse.create(
            req,
            {
                "live_processes":len(processes),
                "registered_profile_types":sorted(discovery),
                "registered_profiles":sum(len(v) for v in discovery.values()),
                "runtime_witness_records":len(witness),
                "evidence_digest":telemetry_digest,
            },
            subject_key,
            now,
        )
        response.verify(subject_key,req,now)

        report={
            "stage":39,
            "kind":"live Open5GS v2.7.6 coverage smoke",
            "open5gs_ref":"v2.7.6",
            "live_processes":len(processes),
            "controlled_nf_types":sorted({row[2] for row in PROCESSES.values()}),
            "registered_profile_expected":EXPECTED_DISCOVERY,
            "registered_profile_observed":{k:len(v) for k,v in discovery.items()},
            "scp_discovery_count":len(scp_rows),
            "runtime_witness_records":len(witness),
            "kie_bound_to_live_evidence":True,
            "telemetry_digest":telemetry_digest,
            "limitations":[
                "Smoke test of process startup, NRF registration/discovery, runtime witness and KIE evidence binding.",
                "NRF is controlled directly as a live process rather than discovered as an NRF profile.",
                "SCP profile discovery is recorded but not required because deployment behavior may not expose it through the same discovery path.",
                "This does not yet inject all Stage38 mutation families into AMF/SMF/PCF native NRF responses.",
                "mTLS/OAuth2 and SEPP-like tests are covered by the separate Stage39 transport probe, not this Open5GS smoke.",
            ],
        }
        (output/"live_open5gs_report.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
        (output/"live_open5gs_evidence.json").write_text(json.dumps(live_evidence,indent=2,ensure_ascii=False)+"\n")
        (output/"live_open5gs_report.md").write_text(
            "# Stage39 live Open5GS coverage\n\n"
            f"- Live processes: {report['live_processes']}\n"
            f"- Controlled NF types: {', '.join(report['controlled_nf_types'])}\n"
            f"- Registered/discovered profile counts: {report['registered_profile_observed']}\n"
            f"- Runtime witness records: {report['runtime_witness_records']}\n"
            f"- KIE bound to live evidence: {report['kie_bound_to_live_evidence']}\n"
        )
        print(json.dumps(report,indent=2,ensure_ascii=False))
    finally:
        stop_all(processes)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    asyncio.run(main_async(args.output))


if __name__=="__main__":
    main()
