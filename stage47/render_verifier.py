#!/usr/bin/env python3
"""Stage47 external verifier service for Render.

Standalone implementation: intentionally does not import Stage44 detector code.
It verifies NFProfile groups received over HTTPS and returns a challenge-bound
verdict plus an execution-host fingerprint. This is an experimental verifier,
not a production authentication service.
"""
import hashlib
import json
import os
import socket
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY=16*1024*1024
PROCESS_NONCE=uuid.uuid4().hex

STAGE51_IDENTITIES={
 "nrf1":{"nf_type":"NRF","endpoint":"127.0.0.10","uuid":"60d1a46c-cb17-41f1-97b0-23e2e8d8f27e"},
 "scp1":{"nf_type":"SCP","endpoint":"127.0.0.11","uuid":"68587210-cb17-41f1-b778-cb0504de424b"},
 "nssf1":{"nf_type":"NSSF","endpoint":"127.0.0.12","uuid":"67c30d06-cb17-41f1-a911-3fec80fe9da1"},
 "nssf2":{"nf_type":"NSSF","endpoint":"127.0.0.13","uuid":"6102db04-cb17-41f1-87aa-fda716b72141"},
 "ausf1":{"nf_type":"AUSF","endpoint":"127.0.0.14","uuid":"67d82330-cb17-41f1-a129-2b5b6aecbd20"},
 "ausf2":{"nf_type":"AUSF","endpoint":"127.0.0.15","uuid":"6127a9ca-cb17-41f1-9432-614e8511394a"},
 "bsf1":{"nf_type":"BSF","endpoint":"127.0.0.16","uuid":"67ed3806-cb17-41f1-aeb4-f5de6ab9f093"},
 "bsf2":{"nf_type":"BSF","endpoint":"127.0.0.17","uuid":"614c8632-cb17-41f1-942e-cb89bf0f65b0"},
 "udm1":{"nf_type":"UDM","endpoint":"127.0.0.18","uuid":"6802f13c-cb17-41f1-84e9-e3c72840941e"},
 "udm2":{"nf_type":"UDM","endpoint":"127.0.0.19","uuid":"6171570a-cb17-41f1-8a52-23e697ea8bb7"},
 "amf1":{"nf_type":"AMF","endpoint":"127.0.0.20","uuid":"68188b5a-cb17-41f1-9015-ad0ac3a479aa"},
 "smf1":{"nf_type":"SMF","endpoint":"127.0.0.21","uuid":"683521de-cb17-41f1-be57-313b7449e9f3"},
 "pcf1":{"nf_type":"PCF","endpoint":"127.0.0.22","uuid":"6843dad0-cb17-41f1-843e-6b58e972449c"}
}
STAGE51_MAP_SHA256=sha(STAGE51_IDENTITIES)

def stage51_false_uuid(slot,trial):
    return str(uuid.uuid5(uuid.NAMESPACE_URL,f"stage51/false/{slot}/{int(trial)}"))


def canon(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def sha(x):
    return hashlib.sha256(canon(x)).hexdigest()

def uuid_tag(u):
    return hashlib.sha256(str(u).lower().encode()).hexdigest()[:32]

def file_hash(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:
        return None

def host_meta():
    return {
        "provider":"render",
        "hostname":socket.gethostname(),
        "machine_id_sha256":file_hash("/etc/machine-id"),
        "boot_id_sha256":file_hash("/proc/sys/kernel/random/boot_id"),
        "process_nonce_sha256":hashlib.sha256(PROCESS_NONCE.encode()).hexdigest(),
        "render_service_id":os.getenv("RENDER_SERVICE_ID"),
        "render_instance_id":os.getenv("RENDER_INSTANCE_ID"),
        "render_service_name":os.getenv("RENDER_SERVICE_NAME"),
        "render_git_commit":os.getenv("RENDER_GIT_COMMIT"),
        "region":os.getenv("RENDER_REGION") or os.getenv("REGION"),
        "pid":os.getpid(),
    }

def check_group(records):
    alerts=[]
    claims=[]
    for row in records:
        slot=row["slot"];p=row["profile"];spec=row["policy"];w=row["witness"];ev=row["lifecycle"]
        if p.get("nfType")!=spec["nf_type"]: alerts.append((slot,"nf_type"))
        if sorted(p.get("ipv4Addresses",[]))!=[spec["endpoint"]]: alerts.append((slot,"endpoint"))
        if (p.get("fqdn") or "")!=(spec.get("fqdn") or ""): alerts.append((slot,"fqdn"))
        if sorted(x.get("serviceName","") for x in p.get("nfServices",[]))!=sorted(spec.get("service_names",[])):
            alerts.append((slot,"services"))
        if p.get("nfStatus")!="REGISTERED": alerts.append((slot,"nf_status"))
        if str(p.get("nfInstanceId","")).lower()!=str(w.get("nf_instance_id","")).lower():
            alerts.append((slot,"witness_uuid"))
        if w.get("nf_type")!=spec["nf_type"] or w.get("endpoint")!=spec["endpoint"]:
            alerts.append((slot,"witness_metadata"))
        if not w.get("process_alive") or not w.get("direct_sbi_tcp_reachable"):
            alerts.append((slot,"witness_liveness"))
        if ev.get("authorized") is not True or ev.get("policy_version")!=1:
            alerts.append((slot,"lifecycle"))
        claims.append((slot,uuid_tag(p.get("nfInstanceId",""))))
    return sorted(set(alerts)),claims

class Handler(BaseHTTPRequestHandler):
    server_version="stage47-render-verifier/1.0"

    def send_json(self,status,obj):
        raw=canon(obj)
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path=="/health":
            self.send_json(200,{"schema":"stage47-render-health-v1","host":host_meta(),
                                "stage51_identity_map_sha256":STAGE51_MAP_SHA256})
        else:
            self.send_json(404,{"error":"not found"})

    def do_POST(self):
        if self.path=="/identity-probe":
            try:
                length=int(self.headers.get("Content-Length","0"))
                if length<=0 or length>MAX_BODY: raise ValueError("invalid body size")
                req=json.loads(self.rfile.read(length))
                if req.get("schema")!="stage51-runtime-probe-request-v1": raise ValueError("schema")
                slot=str(req["slot"]); trial=int(req["trial"]); challenge=str(req["challenge"])
                mode=str(req.get("mode","honest"))
                if slot not in STAGE51_IDENTITIES or mode not in ("honest","lie"): raise ValueError("slot/mode")
                rec=STAGE51_IDENTITIES[slot]
                observed_uuid=rec["uuid"] if mode=="honest" else stage51_false_uuid(slot,trial)
                security={"slot":slot,"trial":trial,"nf_type":rec["nf_type"],"endpoint":rec["endpoint"],
                          "observed_nf_instance_id":observed_uuid,
                          "identity_map_sha256":STAGE51_MAP_SHA256}
                self.send_json(200,{"schema":"stage51-runtime-probe-response-v1",
                                    "challenge":challenge,"security":security,
                                    "security_sha256":sha(security),"host":host_meta()})
            except Exception as e:
                self.send_json(400,{"schema":"stage51-error-v1","error":type(e).__name__+":"+str(e)})
            return
        if self.path!="/verify":
            self.send_json(404,{"error":"not found"});return
        try:
            length=int(self.headers.get("Content-Length","0"))
            if length<=0 or length>MAX_BODY:
                raise ValueError("invalid body size")
            req=json.loads(self.rfile.read(length))
            if req.get("schema")!="stage47-verify-request-v1":
                raise ValueError("schema")
            challenge=str(req["challenge"])
            case_id=str(req["case_id"])
            group=int(req["group"])
            records=req["records"]
            if group not in range(4) or not isinstance(records,list):
                raise ValueError("group/records")
            input_hash=sha(records)
            if input_hash!=req.get("records_sha256"):
                raise ValueError("records hash mismatch")
            t0=time.perf_counter_ns()
            alerts,claims=check_group(records)
            compute_ms=(time.perf_counter_ns()-t0)/1e6
            security={"case_id":case_id,"group":group,"checked":len(records),
                      "records_sha256":input_hash,"alerts":alerts,"uuid_tags":claims}
            response={"schema":"stage47-verify-response-v1","challenge":challenge,
                      "security":security,"verdict_sha256":sha(security),
                      "compute_ms":round(compute_ms,6),"host":host_meta()}
            self.send_json(200,response)
        except Exception as e:
            self.send_json(400,{"schema":"stage47-error-v1","error":type(e).__name__+":"+str(e)})

    def log_message(self,fmt,*args):
        print("STAGE47_HTTP",self.address_string(),fmt%args,flush=True)

def main():
    port=int(os.getenv("PORT","10000"))
    print("STAGE47_RENDER_READY",json.dumps(host_meta(),sort_keys=True),flush=True)
    ThreadingHTTPServer(("0.0.0.0",port),Handler).serve_forever()

if __name__=="__main__":
    main()
