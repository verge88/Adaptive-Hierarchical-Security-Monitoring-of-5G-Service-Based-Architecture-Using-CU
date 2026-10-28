#!/usr/bin/env python3
import asyncio,json,time
from urllib.parse import urlencode
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived,ResponseReceived,StreamEnded
async def get(path):
    r,w=await asyncio.open_connection("127.0.0.10",80)
    c=H2Connection(H2Configuration(client_side=True,header_encoding="utf-8"));c.initiate_connection()
    s=c.get_next_available_stream_id();c.send_headers(s,[(":method","GET"),(":scheme","http"),(":authority","127.0.0.10:80"),(":path",path),("accept","application/json")],end_stream=True)
    w.write(c.data_to_send());await w.drain();body=bytearray();status=None
    while True:
        x=await asyncio.wait_for(r.read(65535),5)
        for e in c.receive_data(x):
            if isinstance(e,ResponseReceived):status=int(dict(e.headers)[":status"])
            elif isinstance(e,DataReceived):body.extend(e.data);c.acknowledge_received_data(e.flow_controlled_length,e.stream_id)
            elif isinstance(e,StreamEnded):
                w.close();await w.wait_closed();return status,json.loads(body)
        w.write(c.data_to_send());await w.drain()
async def main():
    q=urlencode({"target-nf-type":"NSSF","requester-nf-type":"AMF"})
    for _ in range(100):
        try:
            st,d=await get("/nnrf-disc/v1/nf-instances?"+q);rows=d.get("nfInstances",[])
            rows=[x for x in rows if "127.0.0.12" in x.get("ipv4Addresses",[])]
            if st==200 and len(rows)==1:
                r=rows[0];print(json.dumps({"nfInstanceId":r["nfInstanceId"].lower(),"nfType":r["nfType"],"nfStatus":r["nfStatus"],"ipv4Addresses":r.get("ipv4Addresses",[])},sort_keys=True));return
        except Exception:pass
        await asyncio.sleep(.2)
    raise SystemExit("NSSF discovery did not converge")
asyncio.run(main())
