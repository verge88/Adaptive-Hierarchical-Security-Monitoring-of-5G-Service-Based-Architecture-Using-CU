# Stage 14 — Prove real Open5GS SCP forwarding before any new integrity claims

**Pre-registered purpose:** Infrastructure feasibility, not an attack trial.
Stages 10–13 demonstrated selective corruption in a SEPARATE research SCP
and research producer. They NEVER compromised native Open5GS SBI. Stage 14
adds a genuinely running **Open5GS SCP v2.7.6** binary to the existing
real Open5GS NRF/NSSF/AUSF testbed and refuses to claim a real path unless
the raw HTTP/2 requests traverse the native SCP.

## Sources and standardized routing

- Open5GS 2.5.6 release describes native Service Communication Proxy
  indirect communication, based on 3GPP TS 29.500:
  https://open5gs.org/open5gs/release/2022/11/18/release-v2.5.6.html
- Upstream v2.7.6 native SCP config:
  https://raw.githubusercontent.com/open5gs/open5gs/v2.7.6/configs/open5gs/scp.yaml.in
- 3GPP TS 29.500 standardized Target-apiRoot routing:
  https://www.etsi.org/deliver/etsi_ts/129500_129599/129500/16.11.00_60/ts_129500v161100p.pdf

The original native NRF runs at loopback 7777; native NSSFs at 7789/7791.
The new native SCP container uses the same Open5GS image distributor/version
as the NRF, and binds port **127.0.0.1:7802** (research test only).
The external HTTP/2 test consumer sends standard
`3gpp-Sbi-Target-apiRoot: http://nrf:80` or
`3gpp-Sbi-Target-apiRoot: http://nssf:80` (inside Docker bridge network),
not an invented Python relay.

## Pass/fail gates before counting any result

1. Four independent Actions seeds 5401–5404, each with **12 pairs before
   and 12 after SCP restart for each real producer** NRF, NSSF, NSSF2.
   Total per seed = 72 direct-versus-native-SCP pairs; 4 seeds = **288
   pairs** of genuine HTTP/2 requests.
2. NRF discovery must return 200 and EXACTLY the same set of the native
   NSSF nfInstanceIds when sent direct and via SCP. Require at least 2
   genuinely registered NSSF instances; actual AUSF pool remains live.
3. Two native NSSF producer endpoints respond to safe incomplete
   `GET /nnssf-nsselection/v1/network-slice-information` requests.
   Expected 400/404/405/422 may prove HTTP2 handler reachability
   but **is NOT a successful slice-selection transaction**. The native
   SCP must reproduce the same status as direct. Do not infer integrity
   from a generic status alone.
4. Stop the actual **SCP container**. Direct NSSF and NRF remain
   reachable with the same stable AUSF/NSSF registration counts;
   a request to loopback SCP MUST fail at the socket/HTTP2 transport.
   Start the native SCP and establish native routing again.
5. Retain native container image names/digests, Open5GS logs, raw body
   hashes, wire bytes, route metadata and monotonic elapsed time.
   Any failure stops science report aggregation.

No normal Open5GS NF software, configured network function payloads
or native SCP is compromised. This study has **0 injected attacks**.
The NSSF malformed GET tests liveness, not policy semantics; externally
generated consumer queries are not native AMF/UE flows. The lab uses h2c
HTTP/2 without production mTLS/OAuth. There is NO native-NF HMAC origin
receipt, so KIE source attestation is not established here.

## What can be claimed only after a green run

Native Open5GS SCP forwarding to NRF/NSSF is reproducibly supported in
this container topology and the SCP is causally required for the chosen
indirect path. Paired latency overhead is DESCRIPTIVE and is not
evidence of attack detection, security novelty or CU superiority.

Only after passing this prerequisite should Stage 15 instrument real
native NSSF responses with a trustworthy independent origin record,
test permitted laboratory tampering on the actual route, and retain
a trusted plain origin comparison and two-ended monitoring at fair budgets.
Do NOT reuse Stage 10–13 proxy JSON as native NF responses.

## Reproduction

```bash
python -m pip install -r live/requirements.txt
python -m unittest discover -s stage14_tests -v
docker compose -f live/compose.yaml -f live/stage5-compose.yaml \
  -f live/stage14-scp-compose.yaml up -d --pull always
python -m research.nrf_probe --retries 45
python -m research.stage14_native_scp --seed 5401 --output stage14_shard
docker compose -f live/compose.yaml -f live/stage5-compose.yaml \
  -f live/stage14-scp-compose.yaml down --remove-orphans
```

Actions workflow: `.github/workflows/stage14-native-scp.yml`.
