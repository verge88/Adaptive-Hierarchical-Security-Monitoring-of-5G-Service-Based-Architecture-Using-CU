# Stage 3: independent-seed stress testing and spatial-ablation study

## Scientific status and 5G Core integration boundary

Real Open5GS 2.7.6 NRF/AUSF/NSSF containers run in GitHub Actions. Tests
require native NRF service discovery through a real HTTP/2 (h2c) client.
However, CU/KIE flows, lab NF targets and SCP-like independent counters run
ONLY in experimental sidecars: the actual Open5GS NF binaries and NRF
heartbeat are **NOT modified or challenged**.

## Preregistered experiment

Primary comparison: zone-aware versus **local-only adaptive** control-unit
scheduling (spatial-feature ablation). Secondary: fixed round-robin and
seeded random scheduling, with exactly two CU checks every 5 logical seconds,
after 12 training ticks. 96 total ticks per trial. Attacker schedules and
legitimate common-mode traffic bursts are blind to all scheduler inputs.

24 seeds (801..824), in four independent GitHub Actions shards of six seeds.
All four policies replay each seed on new research HTTP/2 sidecars.
For each seed there is an episode of: slow forged report with normal HMAC,
stealth forged report, intermittent modest forgery (mimicry), and signed
forgery + colluding observer, which is a **negative control** and is NOT
included in the primary censored-delay endpoint.

Statistics: event recall per attack type; mean attack detection delay in
accelerated logical seconds (non-detections right-censored to observation
window); 95% seed-paired bootstrap CI for improvement versus local, fixed,
and random baselines; false alerts per 1000 clean checks; HTTP/2 CU bytes
per policy and real wall-clock HTTP/2 CU/NRF round-trip times.

**Do not equate logical attack detection time with measured real-world
5G network latency.** Exact CU count is matched, not on-wire bytes.
An attacker capable of corrupting independent proxy observation can evade
the signature-valid CU consistency detector: a required limitations test.

## How to reproduce

GitHub Actions: .github/workflows/stage3-open5gs.yml
Artifacts: stage3-shard-0..3 and stage3-final-24-seed-results.

Locally, with Docker and Python 3.12:

    python -m pip install -r live/requirements.txt
    docker compose -f live/compose.yaml up -d
    python -m research.nrf_probe --retries 45
    python -m unittest discover -s stage3_tests -v
    python -m research.stage3_experiment --start-seed 801 --count 6 --output shard0
    python -m research.stage3_report --input . --output aggregate
    docker compose -f live/compose.yaml down

CI downloads artifacts and aggregates them, so no Docker is required in
the aggregation job. A confidence interval spanning zero is **not**
evidence of improvement. Scientific novelty requires a literature search;
performance under these controlled synthetic attack assumptions does not
establish clinical, operator or production accuracy.
