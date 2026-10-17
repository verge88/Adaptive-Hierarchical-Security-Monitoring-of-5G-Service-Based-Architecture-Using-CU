from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def b64url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * ((4-len(text)%4)%4))


def issue_token(key,client_id,ttl_s=60):
    payload={"sub":client_id,"aud":"stage39-kie","exp":int(time.time())+ttl_s,"scope":"kie.verify"}
    body=b64url(json.dumps(payload,sort_keys=True,separators=(",",":")).encode())
    sig=b64url(hmac.new(key,body.encode(),hashlib.sha256).digest())
    return body+"."+sig


def verify_token(key,token):
    try:
        body,sig=token.split(".",1)
        expected=b64url(hmac.new(key,body.encode(),hashlib.sha256).digest())
        if not hmac.compare_digest(sig,expected):
            raise ValueError("signature")
        p=json.loads(unb64url(body))
        if int(p.get("exp",0))<int(time.time()) or p.get("aud")!="stage39-kie" or p.get("scope")!="kie.verify":
            raise ValueError("claims")
        return p
    except Exception as exc:
        raise ValueError("invalid bearer token") from exc


def protect_edge_message(key,source_plmn,destination_plmn,payload,nonce):
    core={
        "source_plmn":source_plmn,
        "destination_plmn":destination_plmn,
        "nonce":nonce,
        "payload_sha256":hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
    }
    mac=hmac.new(key,json.dumps(core,sort_keys=True,separators=(",",":")).encode(),hashlib.sha256).hexdigest()
    return {"protected":core,"mac":mac}


def verify_edge_message(key,envelope,payload,expected_destination):
    core=envelope.get("protected",{})
    if core.get("destination_plmn")!=expected_destination:
        return False
    digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    if core.get("payload_sha256")!=digest:
        return False
    expected=hmac.new(key,json.dumps(core,sort_keys=True,separators=(",",":")).encode(),hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(envelope.get("mac","")),expected)


def run(cmd,cwd):
    subprocess.run(cmd,cwd=cwd,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def make_pki(root):
    run([
        "openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1",
        "-subj","/CN=Stage39 Test CA",
        "-addext","basicConstraints=critical,CA:TRUE",
        "-addext","keyUsage=critical,keyCertSign,cRLSign",
        "-addext","subjectKeyIdentifier=hash",
        "-keyout","ca.key","-out","ca.crt"
    ],root)
    run(["openssl","req","-newkey","rsa:2048","-nodes","-subj","/CN=localhost","-keyout","server.key","-out","server.csr"],root)
    (root/"server.ext").write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "extendedKeyUsage=serverAuth\n"
    )
    run(["openssl","x509","-req","-in","server.csr","-CA","ca.crt","-CAkey","ca.key","-CAcreateserial","-days","1","-extfile","server.ext","-out","server.crt"],root)
    run(["openssl","req","-newkey","rsa:2048","-nodes","-subj","/CN=stage39-client","-keyout","client.key","-out","client.csr"],root)
    (root/"client.ext").write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=clientAuth\n"
    )
    run(["openssl","x509","-req","-in","client.csr","-CA","ca.crt","-CAkey","ca.key","-CAcreateserial","-days","1","-extfile","client.ext","-out","client.crt"],root)


class Handler(BaseHTTPRequestHandler):
    token_key=b""
    client_id="stage39-collector"
    client_secret="stage39-ci-secret"

    def log_message(self,fmt,*args):
        return

    def send_json(self,status,doc):
        body=json.dumps(doc,sort_keys=True).encode()
        self.send_response(status)
        self.send_header("content-type","application/json")
        self.send_header("content-length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self.connection.getpeercert():
            self.send_json(401,{"error":"client_certificate_required"})
            return
        if self.path=="/oauth2/token":
            auth=self.headers.get("Authorization","")
            if not auth.startswith("Basic "):
                self.send_json(401,{"error":"invalid_client"})
                return
            try:
                client_id,secret=base64.b64decode(auth[6:]).decode().split(":",1)
            except Exception:
                self.send_json(401,{"error":"invalid_client"})
                return
            length=int(self.headers.get("content-length","0"))
            form=urllib.parse.parse_qs(self.rfile.read(length).decode())
            if client_id!=self.client_id or not hmac.compare_digest(secret,self.client_secret) or form.get("grant_type")!=["client_credentials"]:
                self.send_json(401,{"error":"invalid_client"})
                return
            token=issue_token(self.token_key,client_id)
            self.send_json(200,{"access_token":token,"token_type":"Bearer","expires_in":60,"scope":"kie.verify"})
            return
        if self.path=="/kie":
            auth=self.headers.get("Authorization","")
            if not auth.startswith("Bearer "):
                self.send_json(401,{"error":"invalid_token"})
                return
            try:
                claims=verify_token(self.token_key,auth[7:])
            except ValueError:
                self.send_json(401,{"error":"invalid_token"})
                return
            self.send_json(200,{"accepted":True,"client":claims["sub"],"mtls":True})
            return
        self.send_json(404,{"error":"not_found"})


def opener(ca,cert=None,key=None):
    ctx=ssl.create_default_context(cafile=str(ca))
    if cert and key:
        ctx.load_cert_chain(str(cert),str(key))
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def post(op,url,data,headers):
    req=urllib.request.Request(url,data=data,headers=headers,method="POST")
    try:
        with op.open(req,timeout=5) as resp:
            return resp.status,json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code,json.loads(exc.read())


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        make_pki(root)
        Handler.token_key=os.urandom(32)
        server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(root/"server.crt"),str(root/"server.key"))
        ctx.verify_mode=ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(root/"ca.crt"))
        server.socket=ctx.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        base=f"https://localhost:{server.server_port}"

        no_cert_rejected=False
        try:
            post(opener(root/"ca.crt"),base+"/oauth2/token",b"grant_type=client_credentials",{})
        except Exception:
            no_cert_rejected=True

        client=opener(root/"ca.crt",root/"client.crt",root/"client.key")
        bad_basic="Basic "+base64.b64encode(b"stage39-collector:wrong").decode()
        bad_status,_=post(client,base+"/oauth2/token",b"grant_type=client_credentials",{"Authorization":bad_basic,"Content-Type":"application/x-www-form-urlencoded"})
        good_basic="Basic "+base64.b64encode(b"stage39-collector:stage39-ci-secret").decode()
        token_status,token_doc=post(client,base+"/oauth2/token",b"grant_type=client_credentials",{"Authorization":good_basic,"Content-Type":"application/x-www-form-urlencoded"})
        bad_token_status,_=post(client,base+"/kie",b"{}",{"Authorization":"Bearer invalid"})
        good_status,good_doc=post(client,base+"/kie",b"{}",{"Authorization":"Bearer "+token_doc.get("access_token","")})
        server.shutdown()
        thread.join(timeout=2)

    edge_key=hashlib.sha256(b"stage39-sepp-like-test-key").digest()
    payload={"nfType":"NSSF","service":"nnssf-nsselection"}
    edge=protect_edge_message(edge_key,"001-01","002-02",payload,"edge-nonce-1")
    edge_valid=verify_edge_message(edge_key,edge,payload,"002-02")
    edge_tamper_rejected=not verify_edge_message(edge_key,edge,{"nfType":"NSSF","service":"tampered"},"002-02")
    edge_route_tamper_rejected=not verify_edge_message(edge_key,edge,payload,"999-99")

    report={
        "stage":39,
        "transport_probe":"local GitHub Actions integration test",
        "mtls":{
            "client_certificate_required":no_cert_rejected,
            "valid_client_certificate_accepted":good_status==200,
        },
        "oauth2_client_credentials":{
            "bad_client_rejected":bad_status==401,
            "token_issued":token_status==200,
            "bad_bearer_rejected":bad_token_status==401,
            "valid_bearer_accepted":good_status==200,
        },
        "sepp_like_edge_protection":{
            "valid_envelope_accepted":edge_valid,
            "payload_tamper_rejected":edge_tamper_rejected,
            "destination_tamper_rejected":edge_route_tamper_rejected,
        },
        "resource_response":good_doc,
        "limitations":[
            "Local mTLS/OAuth2 client-credentials enforcement probe, not telecom interoperability certification.",
            "SEPP-like envelope is a boundary integrity test, not a 3GPP N32/SEPP conformance implementation.",
            "Certificates and credentials are ephemeral CI fixtures.",
        ],
    }
    checks=[no_cert_rejected,bad_status==401,token_status==200,bad_token_status==401,good_status==200,edge_valid,edge_tamper_rejected,edge_route_tamper_rejected]
    if not all(checks):
        raise SystemExit("transport security probe failed: "+json.dumps(report))
    (args.output/"transport_security_report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))


if __name__=="__main__":
    main()
