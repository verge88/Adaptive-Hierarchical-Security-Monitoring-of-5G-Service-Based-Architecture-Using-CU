# Adaptive hierarchical 5G SBA monitoring with authenticated CU/KIE

Reproducible **simulation** for a research hypothesis: can zone-aware, risk-adaptive challenge scheduling shorten the delay of detecting compromised 5G Core network functions **at the same CU signalling budget** as periodic polling?

## Scientific status

**This is a 5G SBA-inspired discrete-time simulator, not a 3GPP-compliant 5G core or a live Open5GS deployment.** NF roles AMF/SMF/UDM/AUSF/PCF/NSSF/NRF/SCP are conceptual. No real HTTP/2 messages or live network are sent. The real-world scope and statistical generalization of results are unknown. A model-based advantage is **not** proof that a method has never been published before. Follow-up requires literature/patent comparison and real 5G Core/NRF/SCP instrumentation.

## Architecture, threat model, data mining

- 3 zones x 8 NF instances = 24 NFs; two levels: local NF measurements, per-zone leader with risk score and active signed CU verification; zone-level independent simulated SCP transit counters.
- CU includes NF ID, monotonically increasing cycle, timestamp, 128-bit test nonce, reported count, processing time, HMAC-SHA256. The verifier rejects a stale/replayed cycle, incorrect key or altered payload. For reproducibility the nonce generator is seeded; **not secure for production**.
- An attacker with the NF's signing key replaces the reported number of serviced SBI requests, but cannot alter independently recorded SCP transit counts. Therefore authentication alone cannot prove a report is truthful. This is an explicit threat-model assumption; colluding SCPs are out of scope.
- World dynamics: benign temporal trends, zone-shared noise, legitimate bursts, three classes of forged-report attack. Nine independent attacks and nine legitimate bursts per seed; attack onset after training. There are no data from a real 5G operator.
- Unsupervised Data Mining: baseline median/MAD learned on clean first 300 seconds, temporal exponential moving score, zone-median deviations. No attack labels are given to the detector or scheduler.
- Passive-only detector, fixed round-robin 30-second CU, local-only adaptive CU, zone-aware adaptive CU. **All three CU schemes send exactly 4 CU probes per 5 seconds, hence identical modelled CU overhead.** Risk scheduling includes an aging term to prevent starvation. Decision threshold is an exploratory fixed model parameter; it has **not** been tuned with a held-out real dataset.

## Reproduce

Requires only Python 3.12 standard library; no proprietary data or credentials.

```bash
python -m unittest discover -s tests -v
python -m research.experiment --seeds 12 --output results
```

`results/REPORT.md` provides per-policy metrics, `runs.csv` and `runs.json` contain raw per-seed outcomes, and `summary.json` contains mean values and seed-level paired bootstrap 95% CIs. The experiment is also executed by `.github/workflows/experiment.yml` on every push / pull request and on manual dispatch, and publishes the files as a GitHub Actions artifact.

**Primary endpoint:** attack-event detection latency in seconds, with non-detected events censored to the remaining observation duration. Paired comparison is performed per seed: fixed CU minus zone-adaptive CU. **Secondary endpoints:** event recall, F1 per checked sample, false alarms per 1000 clean checks, and CU bytes/s. Note that the passive comparator performs more observations, so its F1 is not directly comparable to CU methods. The synthetic CU size is assumed to be 260 bytes per request-response; no network-wire measurement was made.

Simulation default: 1,800 s, step 5 s, first 300 s reserved for clean training, 24 NF, 12 fixed seeds (101–112). Attack durations range 150–210 s. Multi-seed paired bootstrap uses 3,000 replicates and fixed seeds.

## Scientific limitations and next steps

This simulation deliberately assumes that attacked NFs leave observable anomalies and that SCP counters remain trustworthy. It does not implement 3GPP-compliant Nnrf heartbeat, dynamic service registration, OAuth2, TLS, HTTP/2 flow-control, lost CUs, real WAN contention, or adaptive adversaries able to falsify proxy observations. Event recall at/near 100% is an indication that these scenarios may be too easy; it must not be used to claim production-grade accuracy. Reported improvement can only support feasibility **under the stated synthetic assumptions**. Later experiments should integrate real Open5GS and an instrumented SCP, calibrate nuisance distributions, inject blind attacks, include collusion and adaptive attack evasion, test external datasets, and compare against stronger alternative schedulers.

## References for implementation stage

- 3GPP TS 23.501 (5G architecture), TS 29.500 (SBI services) and TS 29.510 (NRF NF management).
- 3GPP TS 23.288 (Network Data Analytics Function architecture).
- Uploaded dissertation source: concept of zone leaders/followers, CU report + nonce + authentication code, temporal/spatial features, and cascaded/anomaly detection. This repository tests a **new adaptive sampling hypothesis**, not a full replication of the original SS7/Diameter/SIP evaluation.

## Stage 2: Open5GS-native NRF + HTTP/2 control overlay (separate experimental PR)

The `live/` directory introduces an isolated **real Open5GS NRF, AUSF and NSSF**
Docker Compose configuration, native 5G NRF discovery over HTTP/2 and a separate
HTTP/2 research overlay for authenticated CU and independently instrumented
SCP-like counters. See [live/README.md](live/README.md). Native Open5GS NFs are
**not** modified to accept CU; results are accelerated logical-time tests, not
measured real-life 5G detection latency. This stage is not a replacement for
field traffic validation.
