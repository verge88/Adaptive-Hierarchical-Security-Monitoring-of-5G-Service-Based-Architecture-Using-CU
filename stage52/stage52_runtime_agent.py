#!/usr/bin/env python3
import base64,hashlib,json,os,socket,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CONTROL=Path("/control");WITNESS=Path("/run/stage39/witness")
KEY=Ed25519PrivateKey.generate()
PUB=KEY.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
PUBSHA=hashlib.sha256(PUB).hexdigest()
CONTROL.mkdir(parents=True,exist_ok=True);(CONTROL/"agent_public.pem").write_bytes(PUB)

def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def fhash(p):
    try:return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except Exception:return None
def tcp(host,port=80):
    try:
        with socket.create_connection((host,port),timeout=.4):return True
    except OSError:return False
def find_proc():
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():continue
        try:
            raw=(d/"cmdline").read_bytes()
        except Exception:continue
        if b"open5gs-nssfd" in raw and b"nssf1.yaml" in raw:
            return int(d.name),raw
    return None,None
def runtime_uuid(pid):
    for p in WITNESS.glob("*.tsv"):
        try:
            ps,enum,u=p.read_text().strip().split("\t")
            if int(ps)==pid:return u.lower(),int(enum)
        except Exception:pass
    return None,None
def evidence(challenge):
    pid,cmd=find_proc();alive=pid is not None
    u=enum=exe=cmdh=cgh=None
    if alive:
        u,enum=runtime_uuid(pid)
        try:exe=fhash(f"/proc/{pid}/exe")
        except Exception:exe=None
        cmdh=hashlib.sha256(cmd).hexdigest() if cmd else None
        cgh=fhash(f"/proc/{pid}/cgroup")
    return {"schema":"stage52-live-agent-evidence-v1","challenge":challenge,"slot":"nssf1",
      "nf_type":"NSSF","endpoint":"127.0.0.12","pid":pid,"process_alive":alive,
      "direct_sbi_tcp_reachable":tcp("127.0.0.12"),"nf_instance_id":u,"nf_enum":enum,
      "executable_sha256":exe,"cmdline_sha256":cmdh,"cgroup_sha256":cgh,
      "boot_id_sha256":fhash("/proc/sys/kernel/random/boot_id"),
      "public_key_sha256":PUBSHA,"issued_at_unix_ns":time.time_ns()}
class H(BaseHTTPRequestHandler):
    def sendj(self,o):
        raw=canon(o);self.send_response(200);self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        if self.path=="/health":self.sendj({"schema":"stage52-agent-health-v1","public_key_sha256":PUBSHA})
        else:self.send_response(404);self.end_headers()
    def do_POST(self):
        if self.path!="/attest":self.send_response(404);self.end_headers();return
        n=int(self.headers.get("Content-Length","0"));q=json.loads(self.rfile.read(n));ch=str(q["challenge"])
        e=evidence(ch);sig=KEY.sign(canon(e))
        self.sendj({"schema":"stage52-agent-bundle-v1","evidence":e,"signature_base64":base64.b64encode(sig).decode()})
    def log_message(self,fmt,*args):print("STAGE52_AGENT",fmt%args,flush=True)
print("STAGE52_AGENT_READY",PUBSHA,flush=True)
ThreadingHTTPServer(("127.0.0.1",19052),H).serve_forever()
