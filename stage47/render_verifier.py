#!/usr/bin/env python3
"""Stage47 verifier plus temporary Stage52 external attestation verifier.

Stage52 verifies a GitHub Actions OIDC workload identity and an Ed25519-signed
challenge response emitted by a live Open5GS runtime sidecar. It is deliberately
an external verifier on Render. OIDC proves workflow-job identity, not hardware
identity; the experiment includes a colluding-runner boundary control.
"""
import base64
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY=16*1024*1024
PROCESS_NONCE=uuid.uuid4().hex
OIDC_CONFIG="https://token.actions.githubusercontent.com/.well-known/openid-configuration"

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
        "provider":"render","hostname":socket.gethostname(),
        "machine_id_sha256":file_hash("/etc/machine-id"),
        "boot_id_sha256":file_hash("/proc/sys/kernel/random/boot_id"),
        "process_nonce_sha256":hashlib.sha256(PROCESS_NONCE.encode()).hexdigest(),
        "render_service_id":os.getenv("RENDER_SERVICE_ID"),
        "render_instance_id":os.getenv("RENDER_INSTANCE_ID"),
        "render_service_name":os.getenv("RENDER_SERVICE_NAME"),
        "render_git_commit":os.getenv("RENDER_GIT_COMMIT"),
        "region":os.getenv("RENDER_REGION") or os.getenv("REGION"),"pid":os.getpid(),
    }

def check_group(records):
    alerts=[];claims=[]
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

def b64u_decode(s):
    if isinstance(s,str): s=s.encode()
    return base64.urlsafe_b64decode(s+b"="*((4-len(s)%4)%4))

def der_len(n):
    if n<128:return bytes([n])
    b=n.to_bytes((n.bit_length()+7)//8,"big")
    return bytes([0x80|len(b)])+b

def der_int_bytes(b):
    b=b.lstrip(b"\0") or b"\0"
    if b[0]&0x80:b=b"\0"+b
    return b"\x02"+der_len(len(b))+b

def der_seq(*parts):
    body=b"".join(parts);return b"\x30"+der_len(len(body))+body

def rsa_jwk_pem(jwk):
    n=b64u_decode(jwk["n"]);e=b64u_decode(jwk["e"])
    rsa=der_seq(der_int_bytes(n),der_int_bytes(e))
    alg=bytes.fromhex("300d06092a864886f70d0101010500")
    bit=b"\x03"+der_len(len(rsa)+1)+b"\x00"+rsa
    spki=der_seq(alg,bit)
    body=base64.b64encode(spki).decode()
    return ("-----BEGIN PUBLIC KEY-----\n"+
            "\n".join(body[i:i+64] for i in range(0,len(body),64))+
            "\n-----END PUBLIC KEY-----\n")

def verify_openssl(pub_pem,message,signature,ed25519=False):
    with tempfile.TemporaryDirectory() as td:
        p=Path(td)
        (p/"pub.pem").write_text(pub_pem)
        (p/"msg.bin").write_bytes(message)
        (p/"sig.bin").write_bytes(signature)
        cmd=["openssl","pkeyutl","-verify","-pubin","-inkey",str(p/"pub.pem"),"-rawin",
             "-in",str(p/"msg.bin"),"-sigfile",str(p/"sig.bin")] if ed25519 else             ["openssl","dgst","-sha256","-verify",str(p/"pub.pem"),"-signature",
             str(p/"sig.bin"),str(p/"msg.bin")]
        z=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return z.returncode==0

def fetch_json(url):
    req=urllib.request.Request(url,headers={"User-Agent":"stage52-render-verifier/1"})
    with urllib.request.urlopen(req,timeout=15) as r:
        return json.loads(r.read())

def verify_github_oidc(token,expected_aud,expected):
    parts=token.split(".")
    if len(parts)!=3: return False,{},["jwt_parts"]
    try:
        header=json.loads(b64u_decode(parts[0]));claims=json.loads(b64u_decode(parts[1]))
        sig=b64u_decode(parts[2])
    except Exception:
        return False,{},["jwt_decode"]
    reasons=[]
    if header.get("alg")!="RS256" or not header.get("kid"): reasons.append("jwt_header")
    try:
        cfg=fetch_json(OIDC_CONFIG);jwks=fetch_json(cfg["jwks_uri"])
        jwk=next(k for k in jwks["keys"] if k.get("kid")==header.get("kid"))
        pem=rsa_jwk_pem(jwk)
        if not verify_openssl(pem,(parts[0]+"."+parts[1]).encode(),sig,False):
            reasons.append("jwt_signature")
    except Exception:
        reasons.append("jwt_jwks_verify")
    now=int(time.time())
    if claims.get("iss")!="https://token.actions.githubusercontent.com":reasons.append("issuer")
    aud=claims.get("aud")
    if not (aud==expected_aud or (isinstance(aud,list) and aud==[expected_aud])):reasons.append("audience")
    if int(claims.get("exp",0))<=now:reasons.append("expired")
    if int(claims.get("nbf",0) or 0)>now+5:reasons.append("not_before")
    if abs(now-int(claims.get("iat",0) or 0))>900:reasons.append("issued_at")
    for key in ("repository","ref","sha","workflow_ref"):
        if expected.get(key) is not None and claims.get(key)!=expected.get(key):
            reasons.append("claim_"+key)
    safe={k:claims.get(k) for k in (
        "iss","sub","aud","repository","repository_id","ref","sha","workflow",
        "workflow_ref","run_id","run_attempt","actor","event_name","jti")}
    return not reasons,safe,reasons

def verify_stage52(req):
    token=str(req["oidc_jwt"])
    pubpem=str(req["agent_public_key_pem"])
    bundle=req["agent_bundle"];expected=req["expected"]
    pubsha=hashlib.sha256(pubpem.encode()).hexdigest()
    aud="stage52-runtime:"+pubsha
    oidc_ok,claims,reasons=verify_github_oidc(token,aud,expected)
    evidence=bundle.get("evidence") if isinstance(bundle,dict) else None
    sig_b64=bundle.get("signature_base64") if isinstance(bundle,dict) else None
    if not isinstance(evidence,dict) or not isinstance(sig_b64,str):
        reasons.append("agent_bundle")
        evidence={}
    else:
        try:
            sig=base64.b64decode(sig_b64)
            if not verify_openssl(pubpem,canon(evidence),sig,True):
                reasons.append("agent_signature")
        except Exception:
            reasons.append("agent_signature")
    checks={
      "challenge":evidence.get("challenge")==expected.get("challenge"),
      "public_key":evidence.get("public_key_sha256")==pubsha,
      "slot":evidence.get("slot")=="nssf1",
      "nf_type":evidence.get("nf_type")=="NSSF",
      "endpoint":evidence.get("endpoint")=="127.0.0.12",
      "process_alive":evidence.get("process_alive") is True,
      "sbi_reachable":evidence.get("direct_sbi_tcp_reachable") is True,
      "exe_hash":evidence.get("executable_sha256")==expected.get("executable_sha256"),
      "uuid":str(evidence.get("nf_instance_id","")).lower()==str(expected.get("nf_instance_id","")).lower(),
    }
    for k,v in checks.items():
        if not v:reasons.append("evidence_"+k)
    try:
        if abs(time.time_ns()-int(evidence.get("issued_at_unix_ns",0)))>120_000_000_000:
            reasons.append("evidence_freshness")
    except Exception: reasons.append("evidence_freshness")
    return {
      "schema":"stage52-render-verdict-v1","accepted":oidc_ok and not reasons,
      "reasons":sorted(set(reasons)),"oidc_claims":claims,
      "oidc_token_sha256":hashlib.sha256(token.encode()).hexdigest(),
      "agent_public_key_sha256":pubsha,
      "evidence_sha256":sha(evidence),"render_host":host_meta()
    }

class Handler(BaseHTTPRequestHandler):
    server_version="stage47-stage52-render-verifier/1.0"
    def send_json(self,status,obj):
        raw=canon(obj);self.send_response(status);self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        if self.path=="/health":
            self.send_json(200,{"schema":"stage47-render-health-v1","stage52_verifier":True,"host":host_meta()})
        else:self.send_json(404,{"error":"not found"})
    def do_POST(self):
        if self.path=="/stage52-verify":
            try:
                n=int(self.headers.get("Content-Length","0"))
                if n<=0 or n>MAX_BODY:raise ValueError("invalid body size")
                req=json.loads(self.rfile.read(n))
                if req.get("schema")!="stage52-render-verify-request-v1":raise ValueError("schema")
                self.send_json(200,verify_stage52(req))
            except Exception as e:
                self.send_json(400,{"schema":"stage52-error-v1","error":type(e).__name__+":"+str(e)})
            return
        if self.path!="/verify":self.send_json(404,{"error":"not found"});return
        try:
            n=int(self.headers.get("Content-Length","0"))
            if n<=0 or n>MAX_BODY:raise ValueError("invalid body size")
            req=json.loads(self.rfile.read(n))
            if req.get("schema")!="stage47-verify-request-v1":raise ValueError("schema")
            challenge=str(req["challenge"]);case_id=str(req["case_id"]);group=int(req["group"]);records=req["records"]
            if group not in range(4) or not isinstance(records,list):raise ValueError("group/records")
            input_hash=sha(records)
            if input_hash!=req.get("records_sha256"):raise ValueError("records hash mismatch")
            t0=time.perf_counter_ns();alerts,claims=check_group(records);compute_ms=(time.perf_counter_ns()-t0)/1e6
            security={"case_id":case_id,"group":group,"checked":len(records),
                      "records_sha256":input_hash,"alerts":alerts,"uuid_tags":claims}
            self.send_json(200,{"schema":"stage47-verify-response-v1","challenge":challenge,
                "security":security,"verdict_sha256":sha(security),"compute_ms":round(compute_ms,6),"host":host_meta()})
        except Exception as e:
            self.send_json(400,{"schema":"stage47-error-v1","error":type(e).__name__+":"+str(e)})
    def log_message(self,fmt,*args):
        print("STAGE47_STAGE52_HTTP",self.address_string(),fmt%args,flush=True)

def main():
    port=int(os.getenv("PORT","10000"))
    print("STAGE47_STAGE52_READY",json.dumps(host_meta(),sort_keys=True),flush=True)
    ThreadingHTTPServer(("0.0.0.0",port),Handler).serve_forever()
if __name__=="__main__":main()
