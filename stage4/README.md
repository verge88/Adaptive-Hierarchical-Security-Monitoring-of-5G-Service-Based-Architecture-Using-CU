# Stage 4: bounded-latency CU probe scheduling, 5G SBA HTTP/2 laboratory

**Research status: actual Open5GS NRF/AUSF/NSSF registry and discovery; CU only
in the separate HTTP/2 sidecar research overlay. Open5GS NF binaries are
unmodified. No NRF heartbeat extension or native Open5GS NF compromise.**

## Formal new result under test

For N=6 monitored lab network functions and B=2 control exchanges per
logical tick, the deadline-aware risk scheduler reserves feasibility for
every unchecked NF. Each NF must receive a new authenticated CU check within
G=4 logical ticks of its preceding check (for an unprobed node, time is
measured from the end of clean training). Its choice maximizes a data-mining
risk score over the batches preserving a feasible earliest-deadline schedule.
This is a formal *scheduling bound*, not a guarantee of an attack detection
within G ticks when the attack is observationally stealthy.

At tick t for each candidate batch A of B nodes, sort remaining node
deadlines d_j = previous_check_j + G. A batch is feasible if
d_j >= t + 1 + floor(j/B) for all j=0..N-B-1. Among feasible
batches choose the largest sum of risk-score priorities. Otherwise fail
rather than silently break the guarantee. The guarantee only holds when
G*B >= N and the assumed CU exchange capacity is available.

## Factorial controls, matched 36 independent seeds

Six policies: fixed round robin; seeded random; unbounded local adaptive;
unbounded zone adaptive; bounded local adaptive (spatial-feature ablation);
bounded zone adaptive (proposed combination). All exactly 168 checks per
seed (84 evaluation ticks at 2 checks/tick), separately measured on-wire
HTTP/2 control bytes. The 36 seeds 1201..1236 are split into six CI shards.

Four blind attack episodes per seed, jittered onset and duration: slow
valid-MAC report forgery; stealth valid-MAC report forgery; intermittent
valid-MAC mimicry; coordinated NF+observer collusion as an **explicit
negative control**. Correlated benign zone-wide latency bursts also occur.
Attacker target indices are chosen ahead of time, never passed to the
schedulers. Sampling risk features are obtained from independent lab
observer latency, not from attack labels.

### Preregistered comparisons

Primary: bounded zone versus bounded local (identical max inter-check
bound and CU count, isolate the extra zone-context term).

Secondary: bounded zone versus original zone, fixed, random and local.
Outcome: censored event-detection latency in *accelerated logical seconds*
alongside per-attack recall, p95 censored delay, maximum observed CU gap,
H2 control bytes, false alarm rate, and negative-control misses.
Seed-paired 95% bootstrap intervals. Zero-crossing CI -> INCONCLUSIVE,
irrespective of the point estimate.

## Reproduce

GitHub Actions workflow: .github/workflows/stage4-open5gs.yml.
Six shards and stage4-bounded-cu-research-report artifact contain the
raw per-policy per-seed values, report and native NRF discovery timings.
Manual local commands with Docker and Python 3.12:

    python -m pip install -r live/requirements.txt
    python -m unittest discover -s stage4_tests -v
    docker compose -f live/compose.yaml up -d
    python -m research.nrf_probe --retries 45
    python -m research.stage4_experiment --start-seed 1201 --count 6 --output shard0
    docker compose -f live/compose.yaml down

## Limitations

- Attacks and control units are research-sidecar HTTP/2 work, not actual AMF,
  SMF, NRF, or UPF exploitation.
- Per-policy runs replay same seeded workload, but real on-host service
  latencies are not perfectly controlled; report reproducibility may vary.
- The attack detector is deliberately simple: deviation >3 from the trusted
  observer's cumulative traffic count. For attacks that forge both report
  and independent proxy counters, the system cannot detect by that check.
- Native NRF HTTP/2 round-trip time is measured in wall-clock milliseconds,
  while 5-second ticks in the attack simulations are *logical*, accelerated.
  They must never be equated.
- Equal CU count does not imply equal bytes; both are recorded.
- No mTLS/OAuth, no production crypto key management, no independent traffic
  corpus, no actual 5G NF software modification or operator deployment.
- This work may establish a useful protocol/scheduling design under its
  assumptions but cannot itself establish the absence of prior art.

This stage draws on the uploaded dissertation's hierarchical master/slave
architecture, signed control information unit and temporal/zone feature
concepts. The *new hypothesis* specifically adds deadline-feasible
risk-adaptive management of the active-check budget in a 5G SBA context.
