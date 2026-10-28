#!/usr/bin/env python3
"""Stage50 Render fault-injection endpoint for transport/replay controls."""
import hashlib,json,os,socket,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
CACHE={}
LOCK=threading.Lock()

def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sha(x):return hashlib.sha256(canon(x)).hexdigest()
def fh(p):
    try:return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except Exception:return None
def host():
    return {"provider":"render","hostname":socket.gethostname(),"machine_id_sha256":fh("/etc/machine-id"),
            "boot_id_sha256":fh("/proc/sys/kernel/random/boot_id"),"render_service_id":os.getenv("RENDER_SERVICE_ID"),
            "render_instance_id":os.getenv("RENDER_INSTANCE_ID"),"region":os.getenv("REGION"),"pid":os.getpid()}

class H(BaseHTTPRequestHandler):
    def sendj(self,status,obj):
        raw=canon(obj);self.send_response(status);self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        if self.path=="/health":self.sendj(200,{"schema":"stage50-health-v1","host":host()})
        else:self.sendj(404,{"error":"not found"})
    def do_POST(self):
        if self.path!="/verify":self.sendj(404,{"error":"not found"});return
        n=int(self.headers.get("Content-Length","0"));req=json.loads(self.rfile.read(n))
        fault=req.get("fault","normal");session=req["session_id"]
        if fault=="drop":
            self.connection.shutdown(2);self.connection.close();return
        if fault=="delay":
            time.sleep(float(req.get("delay_s",1.0)))
        records=req["records"]
        if sha(records)!=req["records_sha256"]:
            self.sendj(400,{"error":"records hash"});return
        security={"case_id":req["case_id"],"cycle_id":req["cycle_id"],
                  "records_sha256":req["records_sha256"],"count":len(records)}
        resp={"schema":"stage50-response-v1","challenge":req["challenge"],
              "security":security,"verdict_sha256":sha(security),"host":host()}
        if fault=="wrong_challenge":resp["challenge"]="wrong-"+req["challenge"]
        if fault=="tamper_hash":resp["verdict_sha256"]="00"*32
        if fault=="replay_previous":
            with LOCK:old=CACHE.get(session)
            if old is None:self.sendj(409,{"error":"no previous response"});return
            self.sendj(200,old);return
        with LOCK:CACHE[session]=resp
        self.sendj(200,resp)
    def log_message(self,fmt,*args):print("STAGE50_HTTP",fmt%args,flush=True)

if __name__=="__main__":
    print("STAGE50_READY",json.dumps(host(),sort_keys=True),flush=True)
    ThreadingHTTPServer(("0.0.0.0",int(os.getenv("PORT","10000"))),H).serve_forever()
