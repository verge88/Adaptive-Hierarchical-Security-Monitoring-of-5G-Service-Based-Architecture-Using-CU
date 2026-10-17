from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlencode

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset

ROOT=Path("/opt/stage39")
WORK=Path("/run/stage39/mtls")
CONFIG_ROOT=WORK/"configs"
TLS_ROOT=WORK/"tls"
LOG=Path("/var/log/open5gs")
PORT=443

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
EXPECTED={"NSSF":2,"AUSF":2,"BSF":2,"UDM":2,"AMF":1,"SMF":1,"PCF":1,"SCP":1}
REQUESTER={"NSSF":"AMF","AUSF":"AMF","BSF":"PCF","UDM":"AMF","AMF":"SMF","SMF":"AMF","PCF":"SMF","SCP":"AMF"}


def run(cmd,cwd=None):
    subprocess.run(cmd,cwd=cwd,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def prepare_pki():
    TLS_ROOT.mkdir(parents=True,exist_ok=True)
    run([
        "openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1",
        "-subj","/CN=Stage39 Open5GS mTLS CA",
        "-addext","basicConstraints=critical,CA:TRUE",
        "-addext","keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",str(TLS_ROOT/"ca.key"),"-out",str(TLS_ROOT/"ca.crt"),
    ])
    run([
        "openssl","req","-newkey","rsa:2048","-nodes",
        "-subj","/CN=stage39-open5gs-ci",
        "-keyout",str(TLS_ROOT/"core.key"),
        "-out",str(TLS_ROOT/"core.csr"),
    ])
    sans=",".join(f"IP:127.0.0.{i}" for i in range(10,23))
    ext=TLS_ROOT/"core.ext"
    ext.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        f"subjectAltName={sans}\n"
    )
    run([
        "openssl","x509","-req","-in",str(TLS_ROOT/"core.csr"),
        "-CA",str(TLS_ROOT/"ca.crt"),"-CAkey",str(TLS_ROOT/"ca.key"),
        "-CAcreateserial","-days","1","-extfile",str(ext),
        "-out",str(TLS_ROOT/"core.crt"),
    ])


def tls_block():
    return f"""default:
  tls:
    server:
      scheme: https
      private_key: {TLS_ROOT/'core.key'}
      cert: {TLS_ROOT/'core.crt'}
      verify_client: true
      verify_client_cacert: {TLS_ROOT/'ca.crt'}
    client:
      scheme: https
      cacert: {TLS_ROOT/'ca.crt'}
      client_private_key: {TLS_ROOT/'core.key'}
      client_cert: {TLS_ROOT/'core.crt'}

"""


def prepare_configs():
    CONFIG_ROOT.mkdir(parents=True,exist_ok=True)
    for _,config,_,_ in PROCESSES.values():
        source=ROOT/config
        text=source.read_text()
        text=text.replace("http://","https://")
        text=text.replace("port: 80","port: 443")
        text=text.replace(":80",":443")
        (CONFIG_ROOT/config).write_text(tls_block()+text)


def tcp_ready(host,port=PORT,timeout=0.3):
    try:
        with socket.create_connection((host,port),timeout=timeout):
            return True
    except OSError:
        return False


def wait_tcp(host,seconds=20):
    deadline=time.time()+seconds
    while time.time()<deadline:
        if tcp_ready(host):
            return
        time.sleep(0.1)
    raise RuntimeError(f"TCP not ready {host}:{PORT}")


def client_context(with_certificate=True):
    ctx=ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,cafile=str(TLS_ROOT/"ca.crt")
    )
    if with_certificate:
        ctx.load_cert_chain(
            certfile=str(TLS_ROOT/"core.crt"),
            keyfile=str(TLS_ROOT/"core.key"),
        )
    ctx.set_alpn_protocols(["h2"])
    return ctx


async def h2_get(host,path,with_certificate=True,timeout=5):
    ctx=client_context(with_certificate)
    reader,writer=await asyncio.open_connection(
        host,PORT,ssl=ctx,server_hostname=host
    )
    conn=H2Connection(H2Configuration(client_side=True,header_encoding="utf-8"))
    body=bytearray()
    status=None
    try:
        sslobj=writer.get_extra_info("ssl_object")
        if sslobj is None or sslobj.selected_alpn_protocol()!="h2":
            raise RuntimeError("TLS connection did not negotiate h2")
        conn.initiate_connection()
        stream=conn.get_next_available_stream_id()
        conn.send_headers(stream,[
            (":method","GET"),(":scheme","https"),
            (":authority",f"{host}:{PORT}"),(":path",path),
            ("accept","application/json"),
            ("user-agent","stage39-open5gs-mtls-probe"),
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
                    return status,bytes(body),sslobj.version(),sslobj.cipher()
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


async def discover(typ):
    q=urlencode({"target-nf-type":typ,"requester-nf-type":REQUESTER[typ]})
    status,body,tls_version,cipher=await h2_get(
        "127.0.0.10",f"/nnrf-disc/v1/nf-instances?{q}"
    )
    if status!=200:
        raise RuntimeError(f"mTLS discovery {typ} status {status}: {body[:500]!r}")
    doc=json.loads(body)
    rows=doc.get("nfInstances")
    if not isinstance(rows,list):
        raise RuntimeError(f"mTLS discovery {typ} missing nfInstances")
    return rows,tls_version,cipher


def log_tail(slot):
    p=LOG/f"stage39-mtls-{slot}.log"
    return p.read_text(errors="replace")[-5000:] if p.exists() else ""


def start(slot):
    binary,config,_,_=PROCESSES[slot]
    handle=open(LOG/f"stage39-mtls-{slot}.log","ab",buffering=0)
    return subprocess.Popen(
        [binary,"-c",str(CONFIG_ROOT/config)],
        stdout=handle,stderr=subprocess.STDOUT,start_new_session=True,
        env={**os.environ,"STAGE38_WITNESS_DIR":"/run/stage39/mtls-witness"},
    )


def stop_all(processes):
    for p in processes.values():
        if p.poll() is None:
            try:
                os.killpg(p.pid,signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline=time.time()+5
    while time.time()<deadline and any(p.poll() is None for p in processes.values()):
        time.sleep(0.05)
    for p in processes.values():
        if p.poll() is None:
            try:
                os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:
                pass


async def main_async(output):
    output.mkdir(parents=True,exist_ok=True)
    (Path("/run/stage39/mtls-witness")).mkdir(parents=True,exist_ok=True)
    prepare_pki()
    prepare_configs()
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
                wait_tcp(endpoint)
            except Exception as exc:
                raise RuntimeError(
                    f"{slot} mTLS endpoint failed: {exc}; log={log_tail(slot)}"
                )

        observed={}
        tls_versions=set()
        ciphers=set()
        deadline=time.time()+35
        last=None
        while time.time()<deadline:
            try:
                current={}
                ok=True
                for typ,count in EXPECTED.items():
                    rows,tls_version,cipher=await discover(typ)
                    current[typ]=len(rows)
                    tls_versions.add(tls_version)
                    ciphers.add(cipher[0] if cipher else "unknown")
                    if len(rows)!=count:
                        ok=False
                if ok:
                    observed=current
                    break
                last=current
            except Exception as exc:
                last=f"{type(exc).__name__}: {exc}"
            await asyncio.sleep(0.2)
        if not observed:
            tails={slot:log_tail(slot) for slot in PROCESSES}
            raise RuntimeError(f"mTLS convergence failed: {last}; logs={tails}")

        unauthenticated_rejected=False
        try:
            q=urlencode({"target-nf-type":"NSSF","requester-nf-type":"AMF"})
            await h2_get(
                "127.0.0.10",
                f"/nnrf-disc/v1/nf-instances?{q}",
                with_certificate=False,
                timeout=3,
            )
        except Exception:
            unauthenticated_rejected=True
        if not unauthenticated_rejected:
            raise RuntimeError("Open5GS mTLS NRF accepted a client without certificate")

        report={
            "stage":39,
            "kind":"live Open5GS v2.7.6 mutual-TLS SBI smoke",
            "open5gs_ref":"v2.7.6",
            "live_processes":len(processes),
            "controlled_nf_types":sorted({row[2] for row in PROCESSES.values()}),
            "registered_profile_expected":EXPECTED,
            "registered_profile_observed":observed,
            "mutual_tls":{
                "open5gs_sbi_servers_require_client_certificate":True,
                "probe_without_client_certificate_rejected":unauthenticated_rejected,
                "authenticated_discovery_succeeded":True,
                "tls_versions":sorted(tls_versions),
                "ciphers":sorted(ciphers),
                "certificate_model":"single short-lived CI certificate with SANs for all loopback NF endpoints",
            },
            "limitations":[
                "This verifies Open5GS SBI mutual TLS in the live CI testbed, not per-NF production PKI identity separation.",
                "A single ephemeral certificate is intentionally shared by the CI NFs; certificate issuance/revocation operations are not evaluated.",
                "OAuth2 client-credentials remains a separate Stage39 transport probe because Open5GS v2.7.6 source does not expose an implemented NRF OAuth2 token handler in this testbed.",
                "This is not 3GPP security conformance certification.",
            ],
        }
        (output/"live_open5gs_mtls_report.json").write_text(
            json.dumps(report,indent=2)+"\n"
        )
        (output/"live_open5gs_mtls_report.md").write_text(
            "# Stage39 live Open5GS mTLS SBI\n\n"
            f"- Live Open5GS processes: {len(processes)}\n"
            f"- Discovery counts: {observed}\n"
            f"- Client without certificate rejected: {unauthenticated_rejected}\n"
            f"- Authenticated mTLS discovery: success\n"
            f"- TLS versions: {', '.join(sorted(tls_versions))}\n"
            f"- Ciphers: {', '.join(sorted(ciphers))}\n"
        )
        print(json.dumps(report,indent=2))
    finally:
        stop_all(processes)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    asyncio.run(main_async(args.output))


if __name__=="__main__":
    main()
