# Stage 6 — NRF-only control, randomized fault onset, masked telemetry

**Scope:** real native Open5GS NRF, AUSF x2 and NSSF x2; eight administrative
stop/restart episodes per GitHub runner, with four independent runner shards
(32 real native NF outages). Signed CU is an *external* research HTTP/2 agent,
not an extension to native Open5GS NF binaries or NRF heartbeat.

## Experimental question

Does the observed zonal risk-adaptive advantage arise from Data Mining and
active authenticated CU monitoring, or largely from an existing NRF
registration-loss signal? A competing NRF-only detector gets the real type
registration counts **without issuing any CU challenges**. Its alerts are
type-level (AUSF/NSSF), not instance-level.

Each CI runner tests four actual NF processes in two signal conditions:

* live: real NRF counts available to zonal scheduling;
* masked: the research scheduler is deliberately given constant healthy
  NRF counts, even though Open5GS NRF continues to work and is independently
  observed for the NRF-only comparator.

There are 32 genuine container outages across four independent CI runners.
The order of NF targets and test modes is randomized and balanced per runner.

## Anti-leakage and timing

The CU schedulers start **before** the actual NF is stopped.
Their stop injection phase is randomized relative to the probe cadence.
The event timestamp is recorded after actual Docker stop returns.
All outcomes are elapsed monotonic WALL seconds, not synthetic time.

Controls: fixed (two CUs per tick), deadline-bounded local risk, deadline-
bounded zonal risk, genuine NRF-only baseline, and an inert masked-NRF-only
negative control. Three active methods each send exactly two CU challenges
per tick. Bounded methods guarantee at most 3 scheduling ticks between
active checks, not a wall-time service-level deadline.

The primary test is the *difference of zonal benefits*:
(local minus zone detection delay with live NRF) minus
(local minus zone detection delay with masked NRF).
The masked ablation changes only the NRF features available to the zonal
scheduler. The service stop events remain real, and the NRF always remains
running. 95% bootstrap CIs resample the entire CI-runner clusters.

## Reproduce

Run the GitHub Actions workflow in
.github/workflows/stage6-nrf-ablation.yml.
It produces four stage6-shard-N archives with real NRF response traces,
native HTTP/2 probe records and policy decisions, then a consolidated
stage6-nrf-ablation-native-report artifact.

Local: Python 3.12, Docker Compose, isolated Open5GS test environment.

    python -m pip install -r live/requirements.txt
    python -m unittest discover -s stage6_tests -v
    docker compose -f live/compose.yaml -f live/stage5-compose.yaml up -d
    python -m research.nrf_probe --retries 45
    python -m research.stage6_native --seed 1801 --output stage6_run
    docker compose -f live/compose.yaml -f live/stage5-compose.yaml down

## Research limitations

NRF-only alarms have NF-*type* resolution; CU observations have instance
resolution. They cannot be treated as functionally identical detectors.
Masking NRF telemetry is a deliberate experimental feed intervention,
not a real radio/core outage. Faults are actual native NF availability
loss via Docker stop, not insider compromise or fabricated NF counters.
HMAC authenticates a separate research agent's observation, not internal
Open5GS NF state. No TLS/OAuth, operator traffic, NWDAF implementation,
or standard-compliant native CU extension is demonstrated.

A gain that disappears under NRF masking means it depends on a status
signal already supplied by 5G Core, not proof of novel Data Mining ability.
Even a positive primary interaction is not a demonstration of scientific
priority over the state of the art.
