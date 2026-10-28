#!/usr/bin/env python3
import argparse,copy,hashlib,json,os,urllib.request,uuid
from pathlib import Path
def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def post(url,obj,timeout=30):
    raw=canon(obj);q=urllib.request.Request(url,data=raw,headers={"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(q,timeout=timeout) as r:return json.loads(r.read())
def attest(agent,challenge):
    return post(agent.rstrip("/")+"/attest",{"challenge":challenge})
def verify(render,token,pub,bundle,expected):
    return post(render.rstrip("/")+"/stage52-verify",{"schema":"stage52-render-verify-request-v1",
      "oidc_jwt":token,"agent_public_key_pem":pub,"agent_bundle":bundle,"expected":expected},60)
def main():
    a=argparse.ArgumentParser();a.add_argument("--agent",required=True);a.add_argument("--render",required=True)
    a.add_argument("--token-file",required=True);a.add_argument("--pub",required=True);a.add_argument("--profile",required=True)
    a.add_argument("--exe-hash",required=True);a.add_argument("--mode",choices=["matrix","dead","restart"],required=True);a.add_argument("--out",required=True)
    x=a.parse_args();token=Path(x.token_file).read_text().strip();pub=Path(x.pub).read_text();prof=json.loads(Path(x.profile).read_text())
    base={"repository":os.environ["GITHUB_REPOSITORY"],"ref":os.environ["GITHUB_REF"],"sha":os.environ["GITHUB_SHA"],
          "executable_sha256":x.exe_hash,"nf_instance_id":prof["nfInstanceId"]}
    ch=uuid.uuid4().hex;b=attest(x.agent,ch);e={**base,"challenge":ch};v=verify(x.render,token,pub,b,e)
    if x.mode in ("matrix","restart") and not v.get("accepted"):raise SystemExit("honest/restart rejected "+json.dumps(v))
    if x.mode=="dead" and v.get("accepted"):raise SystemExit("dead process accepted")
    out={"mode":x.mode,"primary":v,"agent_evidence":b["evidence"]}
    if x.mode=="matrix":
        ch2=uuid.uuid4().hex;vr=verify(x.render,token,pub,b,{**base,"challenge":ch2})
        tb=copy.deepcopy(b);tb["evidence"]["executable_sha256"]="00"*32
        vt=verify(x.render,token,pub,tb,e)
        if vr.get("accepted") or vt.get("accepted"):raise SystemExit("negative control accepted")
        out["replay"]=vr;out["tamper"]=vt
    Path(x.out).write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps({"mode":x.mode,"accepted":v.get("accepted"),"reasons":v.get("reasons"),
      "oidc_claims":v.get("oidc_claims"),"agent":b["evidence"]},indent=2))
if __name__=="__main__":main()
