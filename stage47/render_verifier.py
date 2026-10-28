#!/usr/bin/env python3
"""Stage47 verifier with temporary Stage50 transport-fault test endpoint support."""
import hashlib,json,os,socket,time,uuid,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
MAX_BODY=16*1024*1024
PROCESS_NONCE=uuid.uuid4().hex
CACHE={}
LOCK=threading.Lock()
def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sha(x):return hashlib.sha256(canon(x)).hexdigest()
def uuid_tag(u):return hashlib.sha256(str(u).lower().encode()).hexdigest()[:32]
def file_hash(path):
    try:return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:return None
def host_meta():
    return {"provider":"render","hostname":socket.gethostname(),"machine_id_sha256":file_hash("/etc/machine-id"),
            "boot_id_sha256":file_hash("/proc/sys/kernel/random/boot_id"),
            "process_nonce_sha256":hashlib.sha256(PROCESS_NONCE.encode()).hexdigest(),
            "render_service_id":os.getenv("RENDER_SERVICE_ID"),"render_instance_id":os.getenv("RENDER_INSTANCE_ID"),
            "render_service_name":os.getenv("RENDER_SERVICE_NAME"),"render_git_commit":os.getenv("RENDER_GIT_COMMIT"),
            "region":os.getenv("RENDER_REGION") or os.getenv("REGION"),"pid":os.getpid()}
def check_group(records):
    alerts=[];claims=[]
    for row in records:
        slot=row["slot"];p=row["profile"];spec=row["policy"];w=row["witness"];ev=row["lifecycle"]
        if p.get("nfType")!=spec["nf_type"]:alerts.append((slot,"nf_type"))
        if sorted(p.get("ipv4Addresses",[]))!=[spec["endpoint"]]:alerts.append((slot,"endpoint"))
        if (p.get("fqdn") or "")!=(spec.get("fqdn") or ""):alerts.append((slot,"fqdn"))
        if sorted(x.get("serviceName","") for x in p.get("nfServices",[]))!=sorted(spec.get("service_names",[])):alerts.append((slot,"services"))
        if p.get("nfStatus")!="REGISTERED":alerts.append((slot,"nf_status"))
        if str(p.get("nfInstanceId","")).lower()!=str(w.get("nf_instance_id","")).lower():alerts.append((slot,"witness_uuid"))
        if w.get("nf_type")!=spec["nf_type"] or w.get("endpoint")!=spec["endpoint"]:alerts.append((slot,"witness_metadata"))
        if not w.get("process_alive") or not w.get("direct_sbi_tcp_reachable"):alerts.append((slot,"witness_liveness"))
        if ev.get("authorized") is not True or ev.get("policy_version")!=1:alerts.append((slot,"lifecycle"))
        claims.append((slot,uuid_tag(p.get("nfInstanceId",""))))
    return sorted(set(alerts)),claims
class Handler(BaseHTTPRequestHandler):
    server_version="stage47-stage50-render/1.0"
    def send_json(self,status,obj):
        raw=canon(obj);self.send_response(status);self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        if self.path=="/health":self.send_json(200,{"schema":"stage50-health-v1","stage47_schema":"stage47-render-health-v1","host":host_meta()})
        else:self.send_json(404,{"error":"not found"})
    def do_POST(self):
        if self.path!="/verify":self.send_json(404,{"error":"not found"});return
        try:
            length=int(self.headers.get("Content-Length","0"))
            if length<=0 or length>MAX_BODY:raise ValueError("invalid body size")
            req=json.loads(self.rfile.read(length))
            if req.get("schema")=="stage50-request-v1":return self.stage50(req)
            if req.get("schema")!="stage47-verify-request-v1":raise ValueError("schema")
            challenge=str(req["challenge"]);case_id=str(req["case_id"]);group=int(req["group"]);records=req["records"]
            if group not in range(4) or not isinstance(records,list):raise ValueError("group/records")
            input_hash=sha(records)
            if input_hash!=req.get("records_sha256"):raise ValueError("records hash mismatch")
            t0=time.perf_counter_ns();alerts,claims=check_group(records);compute_ms=(time.perf_counter_ns()-t0)/1e6
            security={"case_id":case_id,"group":group,"checked":len(records),"records_sha256":input_hash,"alerts":alerts,"uuid_tags":claims}
            self.send_json(200,{"schema":"stage47-verify-response-v1","challenge":challenge,"security":security,
                                "verdict_sha256":sha(security),"compute_ms":round(compute_ms,6),"host":host_meta()})
        except Exception as e:
            try:self.send_json(400,{"schema":"stage47-error-v1","error":type(e).__name__+":"+str(e)})
            except Exception:pass
    def stage50(self,req):
        fault=req.get("fault","normal");session=req["session_id"]
        if fault=="drop":
            self.connection.shutdown(2);self.connection.close();return
        if fault=="delay":time.sleep(float(req.get("delay_s",1.0)))
        records=req["records"]
        if sha(records)!=req["records_sha256"]:self.send_json(400,{"error":"records hash"});return
        security={"case_id":req["case_id"],"cycle_id":req["cycle_id"],"records_sha256":req["records_sha256"],"count":len(records)}
        resp={"schema":"stage50-response-v1","challenge":req["challenge"],"security":security,
              "verdict_sha256":sha(security),"host":host_meta()}
        if fault=="wrong_challenge":resp["challenge"]="wrong-"+req["challenge"]
        if fault=="tamper_hash":resp["verdict_sha256"]="00"*32
        if fault=="replay_previous":
            with LOCK:old=CACHE.get(session)
            if old is None:self.send_json(409,{"error":"no previous response"});return
            self.send_json(200,old);return
        with LOCK:CACHE[session]=resp
        self.send_json(200,resp)
    def log_message(self,fmt,*args):print("STAGE47_STAGE50_HTTP",self.address_string(),fmt%args,flush=True)
if __name__=="__main__":
    print("STAGE47_STAGE50_READY",json.dumps(host_meta(),sort_keys=True),flush=True)
    ThreadingHTTPServer(("0.0.0.0",int(os.getenv("PORT","10000"))),Handler).serve_forever()
