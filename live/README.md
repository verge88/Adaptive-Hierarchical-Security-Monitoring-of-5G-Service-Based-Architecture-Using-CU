# Stage 2: real Open5GS NRF and live HTTP/2 CU overlay

**Scope boundary:** The Docker containers run **real Open5GS v2.7.6** NRF,
AUSF and NSSF; these Open5GS NF instances register via their native 5G SBA.
The client verifies `GET /nnrf-disc/v1/nf-instances` over actual HTTP/2 h2c.
**Control units (CU/KIE) and the SCP-like proxy run only in LAB-OWNED
HTTP/2 sidecars, NOT inside native Open5GS functions.** No Open5GS NF binary
is patched. Consequently the experiment does **not** validate CU placement in
unmodified 3GPP SBI/NRF heartbeat messages or actual operator signalling.

## Reproduce

Requirements: Docker with Compose, Python 3.12+, no live telecom traffic.

```
python -m pip install -r live/requirements.txt
docker compose -f live/compose.yaml up -d --pull always
python -m research.nrf_probe --retries 45
python -m unittest discover -s live_tests -v
python -m research.live_experiment --seeds 6 --output live_results
docker compose -f live/compose.yaml down
```

GitHub Actions runs all steps under `.github/workflows/live-open5gs.yml`,
uploading `live_results/` and container logs. Images are pinned to the
third-party `ghcr.io/borjis131/{nrf,ausf,nssf}:v2.7.6` tag (not image digests),
which is a reproducibility limitation; Docker downloads are network-dependent.

## Research protocol

- Real NRF responds to service discovery for independently running Open5GS AUSF.
- Three explicit research policies: fixed round-robin, local robust-median/MAD
  latency-risk adaptive polling and zone-median-context adaptive polling.
- Six controlled LAB NF sidecars, two zones, two signed CU challenges per logical
  tick (equal challenge count); replay and modified-challenge rejection.
- SCP-like instrumented h2c proxy independently observes every successful
  forwarded lab service operation. Network traffic truly traverses HTTP/2; it
  is not the simulator from Stage 1.
- Three report-forgery attacks per seed. Attacker holds valid CU signing key;
  false cumulative work count has a valid HMAC, but differs from independent
  proxy observations. Two attacks add extra NF latency and one is stealthy
  regarding latency; separate benign latency bursts are included.
- Warmup 16 logical ticks; 96 ticks total; each tick models 5 logical seconds
  but execution is intentionally accelerated. **Detection delay is logical
  seconds, not wall-clock time or 5G network RTT.**
- H2 transport byte metric includes frames observed by the challenge client in
  both directions; it is not full Ethernet/IP/TCP packet accounting.
- Report paired seed-bootstrap CI; treat zero-crossing CI as inconclusive.

## Scientific limitations

No mutual TLS, OAuth2, real UE/gNB, UPF, 5G subscriber session, live NRF
heartbeat extension, production-grade cryptographic key lifecycle, attack
on actual 5G NF binaries, cross-domain SEPP, compromised SCP, packet-level
network delay experiments or independently collected operator dataset.
All CU signing keys and nonces are deterministic **test only**. The 5G Core
integration currently covers native NRF service discovery, while the CU
path is an opt-in application-level h2c overlay. The goal is to establish
end-to-end protocol plumbing and identify gaps for the subsequent stage, not
to claim definitive scientific novelty or operational attack-detection quality.
