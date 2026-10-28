#!/usr/bin/env python3
"""Stage51: three independent identity-evidence roots for live Stage42 NF profiles.

Root A: NFProfile + witness (treated as one common-mode failure domain).
Root B: Ed25519-signed lifecycle authorization manifest produced by a separate job.
Root C: challenge-bound external runtime identity oracle on Render.

The experiment deliberately compromises roots singly and in pairs, then demonstrates
the explicit boundary where all three roots are compromised consistently.
"""
import argparse, copy, hashlib, json, subprocess, sys, urllib.request, uuid
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"stage44"))
from stage44_multinode_tcp import check_group

TRIALS=8

def canon(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def sha(x):
    return hashlib.sha256(canon(x)).hexdigest()

def false_uuid(slot,trial):
    return str(uuid.uuid5(uuid.NAMESPACE_URL,f"stage51/false/{slot}/{int(trial)}"))

def live_rows(seed):
    out={}
    for slot,row in seed["seed_profiles"].items():
        if row.get("profile_origin")=="stage42_live_http2":
            out[slot]=row
    if len(out)!=12:
        raise AssertionError(f"expected 12 live HTTP/2 profiles, got {len(out)}")
    return out

def write_canon(path,obj):
    Path(path).write_bytes(canon(obj))

def make_manifests(seed_path,outdir):
    seed=json.loads(Path(seed_path).read_text())
    rows=live_rows(seed)
    honest={
      "schema":"stage51-lifecycle-anchor-v1",
      "source_run":39148421353,
      "kind":"honest-authority",
      "records":{slot:{
          "authorized_nf_instance_id":str(row["profile"]["nfInstanceId"]).lower(),
          "nf_type":row["policy"]["nf_type"],
          "endpoint":row["policy"]["endpoint"],
          "policy_version":1
      } for slot,row in sorted(rows.items())}
    }
    compromised={
      "schema":"stage51-lifecycle-anchor-v1",
      "source_run":39148421353,
      "kind":"compromised-authority-fixture",
      "records_by_trial":{
        str(t):{slot:{
          "authorized_nf_instance_id":false_uuid(slot,t),
          "nf_type":row["policy"]["nf_type"],
          "endpoint":row["policy"]["endpoint"],
          "policy_version":1
        } for slot,row in sorted(rows.items())}
        for t in range(TRIALS)
      }
    }
    out=Path(outdir);out.mkdir(parents=True,exist_ok=True)
    write_canon(out/"anchors_honest.json",honest)
    write_canon(out/"anchors_compromised.json",compromised)
    print(json.dumps({"live_slots":len(rows),"trials":TRIALS,
                      "honest_manifest_sha256":hashlib.sha256((out/"anchors_honest.json").read_bytes()).hexdigest(),
                      "compromised_manifest_sha256":hashlib.sha256((out/"anchors_compromised.json").read_bytes()).hexdigest()},indent=2))

def verify_sig(pub,msg,sig):
    p=subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",str(pub),
                      "-rawin","-in",str(msg),"-sigfile",str(sig)],
                     stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    return p.returncode==0

def http_json(url,obj=None,timeout=30):
    if obj is None:
        with urllib.request.urlopen(url,timeout=timeout) as r:return json.loads(r.read())
    raw=canon(obj)
    req=urllib.request.Request(url,data=raw,headers={"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=timeout) as r:return json.loads(r.read())

def validate_probe(resp,challenge,slot,trial,map_hash,host_id):
    if resp.get("schema")!="stage51-runtime-probe-response-v1":return False,"schema"
    if resp.get("challenge")!=challenge:return False,"challenge"
    sec=resp.get("security",{})
    if sec.get("slot")!=slot or sec.get("trial")!=trial:return False,"binding"
    if sec.get("identity_map_sha256")!=map_hash:return False,"map_hash"
    if resp.get("security_sha256")!=sha(sec):return False,"security_hash"
    if resp.get("host",{}).get("render_instance_id")!=host_id:return False,"host_changed"
    return True,"accepted"

def probe(base,slot,trial,mode,map_hash,host_id):
    challenge=uuid.uuid4().hex
    req={"schema":"stage51-runtime-probe-request-v1","slot":slot,"trial":trial,
         "mode":mode,"challenge":challenge}
    resp=http_json(base.rstrip("/")+"/identity-probe",req,30)
    ok,why=validate_probe(resp,challenge,slot,trial,map_hash,host_id)
    if not ok:raise AssertionError(f"runtime probe rejected {slot}/{trial}/{mode}: {why}")
    return resp,challenge

def evidence_accept(profile_uuid,witness_uuid,anchor_uuid,runtime_uuid,anchor_valid=True,runtime_valid=True):
    vals=[str(profile_uuid).lower(),str(witness_uuid).lower(),str(anchor_uuid).lower(),str(runtime_uuid).lower()]
    return bool(anchor_valid and runtime_valid and len(set(vals))==1)

def baseline_pw_escape(row,slot,trial):
    x=copy.deepcopy(row)
    fake=false_uuid(slot,trial)
    x["profile"]["nfInstanceId"]=fake
    x["witness"]["nf_instance_id"]=fake
    record={"slot":slot,"profile":x["profile"],"policy":x["policy"],"witness":x["witness"],
            "lifecycle":{"authorized":True,"policy_version":1,"cycle":trial}}
    alerts,_=check_group([record])
    return len(alerts)==0

def run(seed_path,anchors_dir,render_url,out_path):
    seed=json.loads(Path(seed_path).read_text())
    rows=live_rows(seed); ad=Path(anchors_dir)
    pub=ad/"lifecycle-public.pem"
    honest_file=ad/"anchors_honest.json"; compromised_file=ad/"anchors_compromised.json"
    if not verify_sig(pub,honest_file,ad/"anchors_honest.sig"):
        raise AssertionError("honest lifecycle signature invalid")
    if not verify_sig(pub,compromised_file,ad/"anchors_compromised.sig"):
        raise AssertionError("compromised-authority fixture signature invalid")
    tampered=ad/"anchors_honest_tampered.json"
    b=bytearray(honest_file.read_bytes()); b[-2]=b[-2]^1; tampered.write_bytes(bytes(b))
    tampered_rejected=not verify_sig(pub,tampered,ad/"anchors_honest.sig")
    if not tampered_rejected:raise AssertionError("tampered lifecycle manifest accepted")
    honest=json.loads(honest_file.read_text())
    compromised=json.loads(compromised_file.read_text())
    pub_sha=hashlib.sha256(pub.read_bytes()).hexdigest()

    health=http_json(render_url.rstrip("/")+"/health")
    host=health["host"]; host_id=host.get("render_instance_id")
    map_hash=health.get("stage51_identity_map_sha256")
    if host.get("provider")!="render" or not host_id or not map_hash:
        raise AssertionError("Render Stage51 oracle unavailable")

    detected={k:0 for k in ("pw_only","pw_plus_anchor","pw_plus_runtime",
                            "anchor_only","runtime_only","anchor_plus_runtime")}
    benign_accepted=0; boundary_escapes=0; baseline_escapes=0; replay_rejected=0
    rows_out=[]
    for trial in range(TRIALS):
      for slot,row in sorted(rows.items()):
        real=str(row["profile"]["nfInstanceId"]).lower()
        if str(row["witness"]["nf_instance_id"]).lower()!=real:
            raise AssertionError("seed profile/witness mismatch "+slot)
        anchor_real=honest["records"][slot]["authorized_nf_instance_id"]
        anchor_fake=compromised["records_by_trial"][str(trial)][slot]["authorized_nf_instance_id"]
        fake=false_uuid(slot,trial)
        if anchor_fake!=fake:raise AssertionError("attack fixture mismatch")

        honest_probe,ch=probe(render_url,slot,trial,"honest",map_hash,host_id)
        lie_probe,_=probe(render_url,slot,trial,"lie",map_hash,host_id)
        runtime_real=honest_probe["security"]["observed_nf_instance_id"].lower()
        runtime_fake=lie_probe["security"]["observed_nf_instance_id"].lower()
        if runtime_real!=real:raise AssertionError("Render honest identity mismatch "+slot)
        if runtime_fake!=fake:raise AssertionError("Render lie fixture mismatch "+slot)

        # Replay the accepted response under a fresh challenge: must be rejected.
        ok,why=validate_probe(honest_probe,uuid.uuid4().hex,slot,trial,map_hash,host_id)
        if ok:raise AssertionError("runtime replay accepted")
        replay_rejected+=1

        if not baseline_pw_escape(row,slot,trial):
            raise AssertionError("Stage44 baseline unexpectedly detected profile+witness common-mode UUID poison")
        baseline_escapes+=1

        if evidence_accept(real,real,anchor_real,runtime_real):
            benign_accepted+=1
        else:raise AssertionError("benign evidence rejected")

        scenarios={
          "pw_only":(fake,fake,anchor_real,runtime_real),
          "pw_plus_anchor":(fake,fake,anchor_fake,runtime_real),
          "pw_plus_runtime":(fake,fake,anchor_real,runtime_fake),
          "anchor_only":(real,real,anchor_fake,runtime_real),
          "runtime_only":(real,real,anchor_real,runtime_fake),
          "anchor_plus_runtime":(real,real,anchor_fake,runtime_fake)
        }
        for kind,vals in scenarios.items():
            if evidence_accept(*vals):
                raise AssertionError("attack escaped: "+kind)
            detected[kind]+=1

        if evidence_accept(fake,fake,anchor_fake,runtime_fake):
            boundary_escapes+=1
        else:raise AssertionError("all-roots compromise did not form consistent false state")

        rows_out.append({"slot":slot,"trial":trial,"real_uuid_sha256":hashlib.sha256(real.encode()).hexdigest(),
                         "false_uuid_sha256":hashlib.sha256(fake.encode()).hexdigest(),
                         "render_instance_id":host_id})

    h2=http_json(render_url.rstrip("/")+"/health")
    if h2["host"].get("render_instance_id")!=host_id or h2.get("stage51_identity_map_sha256")!=map_hash:
        raise AssertionError("Render oracle changed during experiment")

    total=len(rows)*TRIALS
    report={
      "schema":"stage51-independent-evidence-roots-v1",
      "source_run":39148421353,
      "live_nf_slots":len(rows),
      "trials":TRIALS,
      "identity_cases":total,
      "baseline_profile_witness_common_mode_escapes":baseline_escapes,
      "benign_accepted":benign_accepted,
      "detected_by_attack_class":detected,
      "all_single_and_double_root_attacks_detected":all(v==total for v in detected.values()),
      "all_roots_compromised_boundary_escapes":boundary_escapes,
      "runtime_replays_rejected":replay_rejected,
      "tampered_lifecycle_signature_rejected":tampered_rejected,
      "lifecycle_public_key_sha256":pub_sha,
      "render_identity_map_sha256":map_hash,
      "render_host":host,
      "trust_model":{
        "root_A":"NFProfile and witness are one common-mode failure domain",
        "root_B":"Ed25519-signed lifecycle authorization manifest produced by a separate GitHub Actions authority job",
        "root_C":"challenge-bound runtime identity oracle executed on a pinned external Render instance",
        "decision_rule":"accept identity only when all three roots bind to the same nfInstanceId; otherwise fail closed"
      },
      "limitations":[
        "The Render runtime oracle is an independent external identity service, not the original live Open5GS NF process or a TEE-attested SBI endpoint.",
        "The lifecycle Ed25519 private key is ephemeral inside a GitHub Actions job rather than protected by an HSM.",
        "The experiment uses the 12 Stage42 live HTTP/2 discovery profiles captured in prior evidence; it does not create fresh Open5GS registrations.",
        "Consistent compromise of all three roots remains indistinguishable from a valid state and is intentionally demonstrated as the trust boundary."
      ],
      "cases":rows_out
    }
    if baseline_escapes!=total or benign_accepted!=total or boundary_escapes!=total or replay_rejected!=total:
        raise AssertionError("unexpected aggregate")
    Path(out_path).write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({k:report[k] for k in ("live_nf_slots","trials","identity_cases",
      "baseline_profile_witness_common_mode_escapes","benign_accepted","detected_by_attack_class",
      "all_single_and_double_root_attacks_detected","all_roots_compromised_boundary_escapes",
      "runtime_replays_rejected","tampered_lifecycle_signature_rejected",
      "lifecycle_public_key_sha256","render_identity_map_sha256","render_host")},indent=2,ensure_ascii=False))

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="op",required=True)
    m=sub.add_parser("make-manifests");m.add_argument("--seed",required=True);m.add_argument("--outdir",required=True)
    r=sub.add_parser("run");r.add_argument("--seed",required=True);r.add_argument("--anchors",required=True)
    r.add_argument("--render-url",required=True);r.add_argument("--out",required=True)
    a=ap.parse_args()
    if a.op=="make-manifests":make_manifests(a.seed,a.outdir)
    else:run(a.seed,a.anchors,a.render_url,a.out)
if __name__=="__main__":main()
