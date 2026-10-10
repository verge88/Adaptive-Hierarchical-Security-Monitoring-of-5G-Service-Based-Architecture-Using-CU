# Stage 7: NRF instance-ID control and native-Open5GS-backed HTTP/2 gateway integrity

**Actual environment:** a running Open5GS NRF, two AUSFs, and two NSSFs,
accessed through real HTTP/2 sockets. Real NRF discovery returns instance IDs.

**Injected fault boundary:** Only an *experimental consumer-side HTTP/2 gateway*
is tampered; the gateway sends a lab-defined JSON envelope containing the
selected native NF's actual HTTP status and the known service identifier.
This envelope is not a native Open5GS service response schema. There is no
Open5GS NF binary patch or compromise, no native NF-signed KIE and no
3GPP-compliant NRF heartbeat extension.

## Why these controls matter

Stage 6 used an artificially weakened NRF-only count detector. Here the
online NRF control compares full **nfInstanceId sets**, allowing detection
of profile loss, replacement or turnover without CU. Registration remains
normal in this experiment; it should produce no true-positive alert.

Four classes of competing observer:
- NRF instance-ID set comparison (zero CU);
- passive HTTP status and message-length anomaly detector (zero CU);
- **strong passive full-payload fingerprint** (zero CU);
- signed independent KIE comparison, with fixed, bounded-local or
  bounded-zone risk-based selection (2 KIE per tick each).

The strong full-payload passive comparator might correctly detect both
tampering modes: do not omit or weaken it simply to make KIE look better.
The active KIE authenticates the EXTERNAL attestor's observation of the
native NF status and known service identifier, not internal NF honesty.

Two controlled tampering types: an **equal-length identity substitution**
in the gateway envelope and a **status-code rewrite**. Neither changes
native NRF registration. Eight randomized episodes per independent
GitHub Actions runner (4 native NFs x 2 attack modes). Attacks begin
after the polling system starts, with randomized onset phase.

## Hypothesis and performance

Evaluate paired *real monotonic wall-clock* first-alert delay and event
recall per attack type, with non-detections assigned their remaining
observation horizon for an explicitly horizon-penalized delay.
Track clean-window false alarms, NRF ID changes, matching CU counts,
wire bytes, max CU gap and up-to-date native NRF/CU traces.

Observe different detection granularities: passive payload fingerprints
require a stable previously observed payload. Unlike a signed independent
path, they do not authenticate provenance of the gateway's responses,
but may nonetheless be as fast as or faster than active checks in this lab.

The research scheduler uses online EMA local delay/metadata anomalies
and peer-relative residuals; it is not a trained NWDAF or a validated
machine-learning contribution. No scientific priority or operator-grade
security conclusions can be drawn from this experiment.

## Reproduction

GitHub Actions: `.github/workflows/stage7-integrity.yml`.
Standalone tests: `python -m unittest discover -s stage7_tests -v`.
Run in an isolated Docker-capable environment:

```
python -m pip install -r live/requirements.txt
docker compose -f live/compose.yaml -f live/stage5-compose.yaml up -d
python -m research.nrf_probe --retries 45
python -m research.stage7_integrity --seed 2001 --output stage7_shard
docker compose -f live/compose.yaml -f live/stage5-compose.yaml down
```

The Actions workflow runs independent seeds 2001–2004 in isolated runners
and publishes raw events/traces, a scientific report and diagnostic NF logs.
