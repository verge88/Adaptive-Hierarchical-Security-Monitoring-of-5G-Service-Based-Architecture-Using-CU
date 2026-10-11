# Stage 18 — Blind native Open5GS SCP validation

Stage 18 is the first live transport gate for the Stage-17 directional
e-process.

## What is genuinely native

Every monitored consumer transaction is forwarded through the genuine
containerized **Open5GS v2.7.6 SCP** to the genuine native NRF over HTTP/2 h2c.
The native SCP and NRF binaries are not modified.

The research fault gateway sits **after** the native SCP response. It can alter
only the consumer-facing response copy. Therefore this stage does not claim
that the Open5GS SCP binary itself has been compromised.

## Why a post-SCP gateway

Open5GS does not expose the Stage-17 synthetic signed accounting primitive as a
native attestation interface. Rather than invent such a field inside the NF or
patch the SCP binary, Stage 18 validates the frozen sequential mechanism on a
real SCP/NRF data path and injects faults at an explicit research boundary.

The monitored live scalar is canonical JSON byte accounting:

- trusted side: canonical bytes from an independent nearby request through the
  genuine native SCP to NRF;
- consumer side: canonical bytes returned through the post-SCP research gateway.

The detector receives only these telemetry values and HTTP status metadata.

## Blind separation

GitHub Actions uses three distinct stages:

1. **capture**: starts Open5GS, runs the private post-SCP fault schedule, and
   uploads label-free telemetry and private labels as two different artifacts;
2. **blind-detect**: downloads **only telemetry**. A workflow assertion fails if
   any `private_labels.json` exists. Frozen Stage-17 detectors emit alarms;
3. **audit**: only after blind detection completes, downloads labels and alarms
   and computes event metrics.

The detector module does not import the Stage-18 gateway, attack schedule, or
fault kinds.

## Frozen detectors

No Stage-18 parameter tuning is performed.

Directional e-process parameters are exactly the Stage-17 final values:

- decay = 0.90
- reference = 0.12
- threshold = 5.0
- one-sided p gate = 0.06

Page-Hinkley is also frozen from Stage 17:

- delta = 0.50
- threshold = 8.0
- integrity p gate = 0.08
- mean alpha = 0.10

## Live fault episodes

Each independent runner has 30 clean warm-up ticks followed by 12 balanced
episodes: three instances each of

- `profile_duplicate` — persistent positive signed response growth;
- `profile_drop` — persistent negative signed response shrinkage;
- `padding_sparse` — sparse positive consumer-only mutation;
- `metadata_strip_sparse` — sparse negative consumer-only mutation.

Each episode lasts 12 ticks and is followed by six clean ticks. Episode order is
randomized independently by seed.

Six preregistered hosted runners are used: seeds **8101..8106**.

## Scientific scope

A positive result would show that the frozen directional sequential mechanism
survives movement from synthetic Stage-16 traffic to real HTTP/2 messages on a
native Open5GS SCP/NRF path while remaining blind to the injected labels.

It would **not** establish:

- malicious compromise of the native Open5GS SCP binary;
- production TLS/OAuth/SEPP behavior;
- native NF-generated integrity attestation;
- production 5G Core detection accuracy.

The next stronger gate would require either an instrumented trusted observer at
the native SCP boundary or a controlled Open5GS fault-injection build whose
attack process remains independently orchestrated.


## Verified live result

The live capture itself was frozen in GitHub Actions run **38138615643** before
blind detector processing. All six Open5GS runners completed successfully and
uploaded telemetry and private labels as separate artifacts.

A path-only postprocessing bug initially prevented the detector from locating
`telemetry.json`. No detector metrics were produced by that failed attempt.
The fixed postprocess workflow reused the exact capture artifacts from run
38138615643 rather than re-capturing traffic.

Blind postprocessing run **38138724214** completed successfully.

Across six independent hosted Open5GS runners (seeds 8101..8106):

| Detector | Event recall | Horizon-penalized delay (ticks) | FA / 1000 clean ticks |
|---|---:|---:|---:|
| Page-Hinkley (Stage-17 frozen) | 0.333 | **9.62** | 0.000 |
| **Directional e-process (Stage-17 frozen)** | **0.500** | 10.00 | 0.000 |

Paired runner-level effect, directional minus Page-Hinkley:

- event recall: **+0.167**, 95% runner-cluster bootstrap CI
  **[+0.097, +0.222]**;
- horizon-penalized delay: **+0.37 ticks**, 95% CI
  **[-0.06, +0.85]**;
- false alarms / 1000 clean ticks: **0.000** for both.

Per-family recall:

| Fault family | Page-Hinkley | Directional e-process |
|---|---:|---:|
| profile_drop | 0.722 | **1.000** |
| profile_duplicate | 0.611 | **1.000** |
| metadata_strip_sparse | 0.000 | 0.000 |
| padding_sparse | 0.000 | 0.000 |

### Interpretation

The directional mechanism therefore transfers to real HTTP/2 traffic through
native Open5GS SCP/NRF for **persistent signed response tampering** and improves
event recall without increasing false alarms.

Stage 18 does **not** demonstrate a delay improvement: the runner-cluster CI
crosses zero. More importantly, both frozen detectors completely miss the sparse
live mutation families. The next detector iteration should target sparse
evidence accumulation while preserving the blind capture/evaluation split; the
Stage-18 live artifacts must now be treated as evaluation data and must not be
used for tuning.
