"""Stage14: genuine native Open5GS SCP forwarding of genuine NRF/NSSF SBI.

This stage is an INFRASTRUCTURE FEASIBILITY GATE. It does not modify real NF
responses, induce SCP compromise, or claim CU superiority. Results count as
"native routed" ONLY if live SCP forwards 3GPP-SBI-Target-apiRoot requests,
a stopped SCP prevents those requests while the same native NRF/NSSF remains
directly available, and the restarted SCP restores the route.

All HTTP/2 is loopback h2c to disposable containers. Not production 5G TLS.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import random
import statistics
import time
from urllib.parse import urlsplit

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ResponseReceived, StreamEnded, DataReceived, StreamReset

from .stage5_native import wait_core, nrf_counts

NATIVE_SCP="http://127.0.0.1:7802"
NATIVE_NRF="http://127.0.0.1:7777"
NATIVE_NSSF="http://127.0.0.1:7789"
NATIVE_NSSF2="http://127.0.0.1:7791"
COMPOSE=["docker","compose","-f","live/compose.yaml",
         "-f","live/stage5-compose.yaml",
         "-f","live/stage14-scp-compose.yaml"]
NATIVE_PROBES=12
NRF_PATH="/nnrf-disc/v1/nf-instances?target-nf-type=NSSF&requester-nf-type=AMF"
NSSF_PATH="/nnssf-nsselection/v1/network-slice-information"


@dataclass
class H2Observed:
    status: int
    body: bytes
    headers: dict
    h2_bytes: int
    duration_s: float

    def public(self):
        try:
            j=json.loads(self.body)
        except (ValueError, UnicodeDecodeError):
            j=None
        return dict(status=self.status,
                    response_sha256=hashlib.sha256(self.body).hexdigest(),
                    response_length=len(self.body),
                    json=j,
                    headers={k:v for k,v in self.headers.items()
                             if k in ("content-type","3gpp-sbi-producer-id")},
                    wire_bytes=self.h2_bytes,
                    elapsed_ms=round(self.duration_s*1000,3))


async def h2_exchange(base,path,*,target=None,method="GET",timeout=4):
    """Independent h2c request with optional standardized routing header.

    Raw response retained to avoid mistaking native Open5GS problem+json
    or an empty 204 response for JSON parsing errors.
    """
    url=urlsplit(base)
    if url.scheme!="http" or not url.hostname:
        raise ValueError("Only isolated plain HTTP/2 lab endpoints allowed")
    async def once():
        start=time.monotonic()
        reader,writer=await asyncio.open_connection(url.hostname,url.port or 80)
        connection=H2Connection(H2Configuration(client_side=True,
                                               header_encoding="utf-8"))
        incoming=bytearray()
        status=None
        received_headers={}
        byte_count=0
        try:
            connection.initiate_connection()
            stream=connection.get_next_available_stream_id()
            headers=[(":method",method),(":scheme","http"),
                     (":authority",url.netloc),(":path",path),
                     ("accept","application/json, application/problem+json")]
            if target is not None:
                headers.append(("3gpp-sbi-target-apiroot",target))
            connection.send_headers(stream,headers,end_stream=True)
            out=connection.data_to_send()
            writer.write(out)
            byte_count+=len(out)
            await writer.drain()
            while True:
                chunk=await reader.read(65535)
                if not chunk:
                    raise ConnectionError("Native HTTP2 peer disconnected without complete stream")
                byte_count+=len(chunk)
                for event in connection.receive_data(chunk):
                    if isinstance(event,ResponseReceived) and event.stream_id==stream:
                        received_headers=dict(event.headers)
                        status=int(received_headers[":status"])
                    elif isinstance(event,DataReceived):
                        if event.stream_id==stream:
                            incoming.extend(event.data)
                        connection.acknowledge_received_data(
                            event.flow_controlled_length,event.stream_id)
                    elif isinstance(event,StreamReset) and event.stream_id==stream:
                        raise ConnectionError("Native peer reset H2 stream")
                    elif isinstance(event,StreamEnded) and event.stream_id==stream:
                        if status is None:
                            raise ConnectionError("No native HTTP/2 status")
                        return H2Observed(status,bytes(incoming),
                                          received_headers,byte_count,
                                          time.monotonic()-start)
                out=connection.data_to_send()
                if out:
                    writer.write(out)
                    byte_count+=len(out)
                    await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError,OSError):
                pass
    return await asyncio.wait_for(once(),timeout)


def discovered_nssf_ids(msg):
    """Only allow real NRF-produced Nnrf NF profile results."""
    if msg.status!=200:
        raise AssertionError(f"Expected native NRF HTTP 200, got {msg.status}")
    obj=json.loads(msg.body)
    if not isinstance(obj,dict) or not isinstance(obj.get("nfInstances"),list):
        raise AssertionError("NRF response does not contain NF discovery profiles")
    ids=sorted({p["nfInstanceId"] for p in obj["nfInstances"]
                if isinstance(p,dict) and p.get("nfType")=="NSSF"
                and isinstance(p.get("nfInstanceId"),str)})
    if len(ids)<2:
        raise AssertionError(f"Native NRF has only {len(ids)} genuine NSSF instances")
    return ids


async def compose_command(command):
    proc=await asyncio.create_subprocess_exec(
        *(COMPOSE+command),stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    try:
        out,err=await asyncio.wait_for(proc.communicate(),timeout=45)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"Timed out running Docker Compose {command}")
    if proc.returncode:
        raise RuntimeError(f"Docker Compose {command} exit={proc.returncode}: "
                           +err.decode(errors="replace")[-800:])
    return out.decode(errors="replace")


async def await_scp_ready():
    last=""
    for _ in range(35):
        try:
            r=await h2_exchange(NATIVE_SCP,NRF_PATH,
                                target="http://nrf:80")
            if len(discovered_nssf_ids(r))>=2:
                return
            last=f"HTTP {r.status}"
        except (AssertionError,OSError,TimeoutError,ConnectionError,
                asyncio.TimeoutError) as ex:
            last=type(ex).__name__+": "+str(ex)[:160]
        await asyncio.sleep(.45)
    raise RuntimeError("Native SCP failed to forward valid NRF discovery: "+last)


def assert_nssf_proxy_native(direct,routed):
    # An intentionally incomplete read-only native Nnssf request is safe.
    # 400/404/405 are legitimate native handler error statuses and NOT a
    # successful slice selection. The native SCP must forward same method/
    # path to the real NSSF and return the same error class.
    if direct.status not in (400,404,405,422):
        raise AssertionError(f"Unexpected native NSSF invalid GET {direct.status}")
    if routed.status!=direct.status:
        raise AssertionError(f"SCP {routed.status} differs from native NSSF "
                             f"{direct.status} for identical invalid query")
    # The content can contain dynamic errors and is not required to be
    # byte-identical. This is a routing/liveness test, not integrity evidence.


async def sample_pairs(seed,phase):
    rng=random.Random(seed*1049+(0 if phase=="before" else 2191))
    paths=[
        ("NRF",NATIVE_NRF,NRF_PATH,"http://nrf:80"),
        ("NSSF",NATIVE_NSSF,NSSF_PATH,"http://nssf:80"),
        ("NSSF2",NATIVE_NSSF2,NSSF_PATH,"http://nssf2:80")]
    data=[]
    for j in range(NATIVE_PROBES):
        group=list(paths)
        rng.shuffle(group)
        for label,direct_url,path,target in group:
            # Alternate order to prevent always crediting one endpoint with
            # warm-cache and clock advantages.
            direct_first=rng.randrange(2)==0
            if direct_first:
                d=await h2_exchange(direct_url,path)
                p=await h2_exchange(NATIVE_SCP,path,target=target)
            else:
                p=await h2_exchange(NATIVE_SCP,path,target=target)
                d=await h2_exchange(direct_url,path)
            if label=="NRF":
                direct_set=discovered_nssf_ids(d)
                proxy_set=discovered_nssf_ids(p)
                if direct_set!=proxy_set:
                    raise AssertionError("Native SCP modified NRF NSSF IDs")
            else:
                assert_nssf_proxy_native(d,p)
            data.append(dict(phase=phase,tick=j,kind=label,
                             direct_first=direct_first,
                             target_apiroot=target,
                             true_native_producer_url=direct_url,
                             native_direct=d.public(),
                             forwarded_via_native_scp=p.public(),
                             identical_HTTP_status=d.status==p.status,
                             same_NRF_nf_instance_ids=(
                                 direct_set==proxy_set if label=="NRF" else None)))
    return data


async def run(args):
    await wait_core(NATIVE_NRF,require_registered=True,timeout=70)
    await await_scp_ready()
    before=await nrf_counts(NATIVE_NRF)
    if before.get("NSSF",0)<2 or before.get("AUSF",0)<2:
        raise AssertionError("Real NRF lacks original native NF pool")
    rows=await sample_pairs(args.seed,"before")
    # CAUSAL NEGATIVE CONTROL: kill the REAL binary service. Host's direct
    # native NF socket is still served; same request through proxy must fail.
    await compose_command(["stop","-t","1","scp"])
    await asyncio.sleep(.4)
    negative={"native_scp_stopped":True}
    direct=await h2_exchange(NATIVE_NRF,NRF_PATH)
    negative["native_direct_NRF_status"]=direct.status
    negative["native_direct_NSSF_ids"]=discovered_nssf_ids(direct)
    await h2_exchange(NATIVE_NSSF,NSSF_PATH)  # still reachable
    try:
        routed=await h2_exchange(NATIVE_SCP,NRF_PATH,target="http://nrf:80",
                                 timeout=1.5)
        negative["unexpected_routed_HTTP_status"]=routed.status
        raise AssertionError("Native SCP was stopped but proxy still responded!")
    except (ConnectionRefusedError,ConnectionResetError,
            ConnectionAbortedError,TimeoutError,asyncio.TimeoutError,
            ConnectionError,OSError) as ex:
        negative["proxy_refused_after_native_scp_stop"]=type(ex).__name__
    after_stop=await nrf_counts(NATIVE_NRF)
    if after_stop.get("NSSF")!=before.get("NSSF") or (
        after_stop.get("AUSF")!=before.get("AUSF")):
        raise AssertionError("Native NF registration changed when SCP stopped")
    await compose_command(["start","scp"])
    await await_scp_ready()
    rows+=await sample_pairs(args.seed,"after_restart")
    after=await nrf_counts(NATIVE_NRF)
    if after.get("NSSF")!=before.get("NSSF") or (
        after.get("AUSF")!=before.get("AUSF")):
        raise AssertionError("Real NF registry drifted during SCP restart")

    result=dict(
        stage=14,seed=args.seed,
        real_open5gs_scp_binary=True,
        real_open5gs_nrf_and_nssf_sbi=True,
        native_NF_binaries_modified=False,
        research_proxy_used=False,
        selective_payload_corruption_performed=False,
        consumer="external research h2c probe, NOT native AMF",
        official_indirect_comm_header="3gpp-Sbi-Target-apiRoot",
        protocol="HTTP/2 h2c; no production mTLS",
        nrf_registry_before=before,
        nrf_registry_after_scp_restart=after,
        paired_samples_per_endpoint=NATIVE_PROBES*2,
        direct_proxy_pairs=rows,
        causal_scp_stop_control=negative)
    stats={}
    for label in ("NRF","NSSF","NSSF2"):
        pairs=[x for x in rows if x["kind"]==label]
        diff=[x["forwarded_via_native_scp"]["elapsed_ms"]-
              x["native_direct"]["elapsed_ms"] for x in pairs]
        stats[label]=dict(paired_trials=len(diff),
                          median_direct_ms=statistics.median(
                              x["native_direct"]["elapsed_ms"] for x in pairs),
                          median_via_native_scp_ms=statistics.median(
                              x["forwarded_via_native_scp"]["elapsed_ms"] for x in pairs),
                          median_paired_proxy_extra_ms=statistics.median(diff),
                          mean_paired_proxy_extra_ms=statistics.mean(diff),
                          min_paired_proxy_extra_ms=min(diff),
                          max_paired_proxy_extra_ms=max(diff))
    result["descriptive_timing"]=stats
    output=Path(args.output)
    output.mkdir(parents=True,exist_ok=True)
    (output/"observations.json").write_text(json.dumps(result,indent=2))
    print(f"STAGE14 NATIVE SCP ROUTE CONFIRMED; seed={args.seed}; "
          f"native NRF+NSSF paired transactions={len(rows)}; "
          "real binary stop-isolation and restart validated",flush=True)
    print(json.dumps(stats,indent=2),flush=True)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--seed",required=True,type=int)
    parser.add_argument("--output",default="stage14_shard")
    args=parser.parse_args()
    asyncio.run(run(args))


if __name__=="__main__":
    main()
