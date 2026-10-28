#!/usr/bin/env python3
"""Stage45: randomized logical partitions and adversarial coordinator controls.
Synthetic profiles only; no new live Open5GS measurements or network latency claims.
"""
import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "stage44"))
from stage44_multinode_tcp import (NODES, canon, check_group, envelope, merge,
                                  records_for_node, sha, verify)

def make_seed():
    slots={}
    for i in range(13):
        slot=f"nf{i:02d}"
        endpoint=f"10.42.0.{i+1}"
        uid=f"00000000-0000-4000-8000-{i+1:012x}"
        nf_type=("NSSF","AUSF","BSF","UDM","AMF","SMF","PCF","SCP","NRF")[i%9]
        service=f"n{nf_type.lower()}-service"
        slots[slot]={
            "profile":{"nfInstanceId":uid,"nfType":nf_type,"nfStatus":"REGISTERED",
                       "ipv4Addresses":[endpoint],"fqdn":f"{slot}.example.test",
                       "nfServices":[{"serviceName":service,"ipEndPoints":[{"ipv4Address":endpoint}]}]},
            "policy":{"endpoint":endpoint,"nf_type":nf_type,"fqdn":f"{slot}.example.test",
                      "service_names":[service]},
            "witness":{"nf_instance_id":uid,"nf_type":nf_type,"endpoint":endpoint,
                       "process_alive":True,"direct_sbi_tcp_reachable":True}}
    return {"schema":"stage45-synthetic-seed","source_sha256_report":sha(slots),"seed_profiles":slots}

def coordinator(packets, keys, ph, cycle, require_all=True):
    seen=set()
    alerts=[]
    ids=[]
    for node,blob in packets:
        if node in seen: raise AssertionError("duplicate node summary")
        seen.add(node)
        body=verify(blob,keys[node],"hier",cycle,node,ph)
        if body["count"]!=len(body["uuid_tags"]): raise AssertionError("count mismatch")
        if len({slot for slot,_ in body["uuid_tags"]})!=body["count"]:
            raise AssertionError("duplicated slots within summary")
        alerts.extend(body["alerts"])
        ids.extend(body["uuid_tags"])
    if require_all and seen!=set(range(NODES)): raise AssertionError("missing group")
    if len({slot for slot,_ in ids})!=len(ids): raise AssertionError("cross-group slot overlap")
    return merge(alerts,ids)

def packets_for(groups, keys, ph, cycle):
    out=[]
    for i,rows in enumerate(groups):
        a,ids=check_group(rows)
        body={"schema":"stage45-summary","mode":"hier","cycle":cycle,"node":i,
              "policy_sha256":ph,"count":len(rows),"alerts":a,"uuid_tags":ids}
        out.append((i,envelope(body,keys[i])))
    return out

def rejects(fn):
    try: fn()
    except (AssertionError,KeyError,ValueError,TypeError): return True
    return False

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",default="stage45_report.json")
    args=ap.parse_args()
    seed=make_seed()
    ph=sha(seed["seed_profiles"])
    keys=[hashlib.sha256(f"stage45-test-key-{i}".encode()).digest() for i in range(NODES)]
    report={"schema":"stage45-random-partition-audit-v1",
            "source":"synthetic deterministic NFProfile rows; Stage44 detector implementation",
            "real_network_functions_executed":0,
            "limitations":["No live NF processes, no network timing or physical nodes",
                           "Keys are deterministic test keys, not production secrets",
                           "Coordinator trusts group computations; malicious key-holding nodes are out of scope"],
            "cases":[],"negative_controls":{}}
    for n in (13,1040,4160):
        for trial in range(8):
            for attacked in (False,True):
                rows=[row for node in range(NODES)
                      for row in records_for_node(seed,n,trial,attacked,node)]
                central_alerts,central_ids=check_group(rows)
                expected=merge(central_alerts,central_ids)
                rng=random.Random(450000+n*17+trial*3+int(attacked))
                rng.shuffle(rows)
                groups=[[] for _ in range(NODES)]
                for index,row in enumerate(rows):
                    groups[(index+trial)%NODES].append(row)
                cycle=100+trial
                packets=packets_for(groups,keys,ph,cycle)
                actual=coordinator(packets,keys,ph,cycle)
                assert actual==expected
                if not attacked:assert not actual
                report["cases"].append({"n":n,"trial":trial,"attack":attacked,
                                        "alert_count":len(actual),"equivalent":True,
                                        "alert_sha256":sha(actual)})
                if n==1040 and trial==0 and attacked:
                    tests=report["negative_controls"]
                    tests["missing_group"]=rejects(lambda:coordinator(packets[:-1],keys,ph,cycle))
                    tests["repeated_group"]=rejects(lambda:coordinator(packets+[packets[0]],keys,ph,cycle))
                    tests["replayed_cycle"]=rejects(lambda:coordinator(packets,keys,ph,cycle+1))
                    tests["wrong_policy"]=rejects(lambda:coordinator(packets,keys,"0"*64,cycle))
                    tampered=json.loads(packets[0][1]);tampered["body"]["count"]+=1
                    tests["modified_payload"]=rejects(lambda:coordinator([(0,canon(tampered))]+packets[1:],keys,ph,cycle))
                    overlap=json.loads(packets[1][1]);overlap["body"]["uuid_tags"].append(
                        json.loads(packets[0][1])["body"]["uuid_tags"][0])
                    overlap["body"]["count"]+=1
                    overlap["mac_sha256"]=__import__("hmac").new(keys[1],canon(overlap["body"]),hashlib.sha256).hexdigest()
                    tests["overlapping_slot"]=rejects(lambda:coordinator([packets[0],(1,canon(overlap))]+packets[2:],keys,ph,cycle))
    assert len(report["cases"])==48
    assert len(report["negative_controls"])==6 and all(report["negative_controls"].values())
    report["all_equivalent"]=all(x["equivalent"] for x in report["cases"])
    report["benign_false_alerts"]=sum(x["alert_count"] for x in report["cases"] if not x["attack"])
    report["attacked_nonzero_alert_cases"]=sum(x["alert_count"]>0 for x in report["cases"] if x["attack"])
    Path(args.output).write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({k:report[k] for k in ("all_equivalent","benign_false_alerts","attacked_nonzero_alert_cases","negative_controls")},indent=2))
if __name__=="__main__":main()
