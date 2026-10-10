# Stage 9 — Conditional rare S-NSSAI policy error, registered native NSSF

**Threat boundary:** Native Open5GS NRF, NSSF and NSSF2 genuinely run in Docker,
are registered in NRF, and answer HTTP/2 availability probes. The decisions
for slice selection are calculated in a separate **RESEARCH NSSF-LIKE POLICY
SERVICE**, NOT by the actual native NSSF binaries. The induced fault changes
the RESEARCH SERVICE response on rare test condition (sst=2, sd=0000FF).
It is not exploitation, modification, or corruption of native Open5GS.

## Pre-registered scientific test

Ordinary common S-NSSAI queries return the correct ALLOW decision. During
a controlled fault a specific research context continues answering ordinary
requests correctly, while rare S-NSSAI is incorrectly DENY. Real NRF
registration is unchanged. Monitoring starts before attack injection; onset
phase is randomized. Each lab response contains an unrelated dynamic token
and load value; a fair passive monitor evaluates **semantics using the same
known policy oracle as active methods**, ignoring irrelevant token changes.

Baselines: real NRF nfInstanceId monitoring, passive semantic monitor of
realized traffic, **ordinary active HTTP/2 probing with the same intentional
rare query**, fixed signed CU, local bounded signed CU, and hierarchical
bounded signed CU. Each active method makes exactly 2 probes per tick
(54/case). Ordinary active probes and CU have the SAME oracle, risk model
inputs and target operation; HMAC CU is issued by a **separate research
attestor**, not by native NSSF, and is not claimed to prove native NF
integrity.

Two ordinary-traffic rates: zero rare requests vs 12% rare requests.
Two research stress/target relationships: aligned (target selected within
the high benign-load zone) and unaligned (target selected outside it).
This synthetic prior correlation is deliberately imposed, explicitly
balanced and **is not operator-derived evidence**. 2 repetitions per
factorial cell × 4 independent CI runners = 32 lab policy faults.

Outcome: recall, clean-window false alarms, mean first detection wall time,
duration-penalized misses, active H2 bytes and max check gap. Predefined
paired contrasts:
1. CU fixed versus ordinary active HTTP/2, equal query budget (crypto overhead).
2. CU hierarchy versus CU local (added context).
3. CU hierarchy versus ordinary active HTTP/2 (end-to-end method).
4. CU hierarchy versus passive semantic.

Cluster bootstrap resamples CI runner seed; exact two-sided sign-test p is
reported because four independent runners is a SMALL sample.

## Local reproduction

Requires Python 3.12, Docker Compose, disposable Open5GS:

    python -m pip install -r live/requirements.txt
    python -m unittest discover -s stage9_tests -v
    docker compose -f live/compose.yaml -f live/stage5-compose.yaml up -d
    python -m research.nrf_probe --retries 45
    python -m research.stage9_conditional --seed 2901 --output stage9_shard
    docker compose -f live/compose.yaml -f live/stage5-compose.yaml down

GitHub Actions: .github/workflows/stage9-conditional.yml
Four isolated independent CI seeds 2901..2904, each eight episodes.
The report and raw H2/NRF observation evidence are Actions artifacts.

## Critical limitations

The separate lab policy service is intentionally simplified: it is NOT an
implementation or extension of 3GPP Nnssf_NSSelection. True native Open5GS
NSSF selection, bearer/session handling, legitimate rare-case traffic
distribution and malicious compromise remain untested. "Passive cannot
detect without observed rare traffic" is an information-limitation of
that exact observation model, not proof that CU or hierarchical Data
Mining is uniquely capable; ordinary active HTTP/2 already probes the
same rare branch. Synthetic risk correlation makes it possible for a
hierarchy to gain priority, but the benefit must be compared with strong
local active baselines and replicated. CU's HMAC does not attest internal
NF state, and there is no NWDAF-trained model or scientific priority
claim in this stage.
