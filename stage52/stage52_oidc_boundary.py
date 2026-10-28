#!/usr/bin/env python3
"""Stage52 boundary control: demonstrate that GitHub OIDC attests the job, not the NF process."""
import argparse,base64,hashlib,json,os,subprocess,tempfile,time,urllib.parse,urllib.request,uuid
from pathlib import Path

def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def post(url,obj):
    raw=canon(obj);q=urllib.request.Request(url,data=raw,headers={"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(q,timeout=60) as r:return json.loads(r.read())

def oidc(aud):
    base=os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    sep="&" if "?" in base else "?"
    url=base+sep+"audience="+urllib.parse.quote(aud,safe="")
    q=urllib.request.Request(url,headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with urllib.request.urlopen(q,timeout=30) as r:return json.loads(r.read())["value"]

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--profile",required=True);ap.add_argument("--exe-hash-file",required=True)
    ap.add_argument("--render",required=True);ap.add_argument("--out",required=True);a=ap.parse_args()
    profile=json.loads(Path(a.profile).read_text());exe=Path(a.exe_hash_file).read_text().strip()
    with tempfile.TemporaryDirectory() as td:
        t=Path(td);priv=t/"fake.key";pub=t/"fake.pub";msg=t/"msg";sig=t/"sig"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(priv)],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(["openssl","pkey","-in",str(priv),"-pubout","-out",str(pub)],check=True,stdout=subprocess.DEVNULL)
        pubpem=pub.read_text();pubsha=hashlib.sha256(pubpem.encode()).hexdigest()
        token=oidc("stage52-runtime:"+pubsha)
        challenge=uuid.uuid4().hex
        evidence={"schema":"stage52-live-agent-evidence-v1","challenge":challenge,"slot":"nssf1","nf_type":"NSSF",
          "endpoint":"127.0.0.12","pid":424242,"process_alive":True,"direct_sbi_tcp_reachable":True,
          "nf_instance_id":profile["nfInstanceId"],"nf_enum":9,"executable_sha256":exe,
          "cmdline_sha256":"11"*32,"cgroup_sha256":"22"*32,"boot_id_sha256":"33"*32,
          "public_key_sha256":pubsha,"issued_at_unix_ns":time.time_ns()}
        msg.write_bytes(canon(evidence))
        subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(priv),"-rawin","-in",str(msg),"-out",str(sig)],check=True)
        bundle={"schema":"stage52-agent-bundle-v1","evidence":evidence,
                "signature_base64":base64.b64encode(sig.read_bytes()).decode()}
        expected={"repository":os.environ["GITHUB_REPOSITORY"],"ref":os.environ["GITHUB_REF"],"sha":os.environ["GITHUB_SHA"],
                  "challenge":challenge,"executable_sha256":exe,"nf_instance_id":profile["nfInstanceId"]}
        req={"schema":"stage52-render-verify-request-v1","oidc_jwt":token,
             "agent_public_key_pem":pubpem,"agent_bundle":bundle,"expected":expected}
        verdict=post(a.render.rstrip("/")+"/stage52-verify",req)
    if not verdict.get("accepted"):
        raise SystemExit("boundary control unexpectedly rejected: "+json.dumps(verdict))
    report={"schema":"stage52-oidc-process-boundary-v1","accepted_fabricated_state":True,
      "live_nf_present_in_this_job":False,"verdict":verdict,
      "interpretation":"A job controlling both the OIDC capability and agent key can fabricate process evidence that passes the current verifier. GitHub OIDC authenticates the workflow job, not the NF process or hardware.",
      "required_next_control":"hardware-backed or confidential-VM attestation binding a non-exportable key to measured runtime state"}
    Path(a.out).write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"accepted_fabricated_state":True,"oidc_claims":verdict.get("oidc_claims"),
      "agent_public_key_sha256":verdict.get("agent_public_key_sha256"),"reasons":verdict.get("reasons")},indent=2))
if __name__=="__main__":main()
