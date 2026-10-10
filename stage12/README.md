# Stage 12 — Large-sample reproducibility study (576 selective SCP attacks)

**Purpose.** Increase **injected laboratory attack episodes**, not the
number of distinct attack mechanisms. Stage 11 had 32 selective SCP message
corruptions on four independent GitHub runner clusters. Stage 12 freezes
the tested Stage 11 algorithm implementation and repeats the same
pre-specified 2×4 threat/risk design with far more independent seeds and
independent injections. This is designed to confirm OR reject the previous
negative result for a hedged risk-adaptive CU scheduler, not to optimize
hyperparameters after seeing the test data.

## Pre-registration before the CI run

| Experimental dimension | Prespecified value |
|---|---:|
| Independent GitHub Actions runner containers | **12** |
| Runner seeds | **3601 through 3612** |
| Distinct laboratory attack modes | **2** |
| Synthetic risk regimes | **4** |
| Repetitions of each attack × risk cell on each runner | **6** |
| Actual lab proxy corruption episodes per runner | **48** |
| **Total independent injected lab episodes** | **576** |
| Detector result records per episode | **9** |
| Total paired detector records expected | **5,184** |
| Active verification budget per method/episode | **46** |
| Full trusted two-sided origin checks per episode | **92** |

Design: two dynamic LAB producer-selection corruption modes
(`plausible_choice_change`, `stale_choice_field`), crossed with four
synthetic externally supplied risk conditions (`aligned`,
`misleading`, `neutral`, `switch`). Each 8-cell factorial occurs
six times per runner, and is shuffled with a *different pre-fixed seed*.
Attack onset has its own randomized phase per incident. These are
**576 injections of 2 attack types**, not 576 unique novel attack classes.
All attack transactions, simulated risk regimes, and detector traces
are retained in artifact JSON.

## Scientific primary endpoints

Evaluate three preregistered cluster-level paired differences in the
**worst average time-to-detect across the four risk regimes**:

1. Fixed CU minus hedged CU.
2. Local adaptive CU minus hedged CU.
3. Trusted plain direct producer receipt minus hedged CU.

Positive means the hedged method has a lower penalty; negative means it
is WORSE. The report presents original full-cell results (72 events
per attack×risk cell), pooled results, conditional worst means,
bootstrap confidence intervals *resampling the 12 independent RUNNERS*,
and the exact two-sided runner sign-test p-value. The three primary
comparisons are not independent; multiplicity must be acknowledged.

Secondary outcomes: per-episode recall, clean-window false alerts,
measured monotonic wall time, positive vs negative risk splits, bytes,
same-budget 46 checks for all active schemes, full trusted two-sided
92-check upper-bound baseline, and gap≤3 for bounded schemes. Unobserved
alarms receive their episode duration as a stated penalty; this is not
an unbiased survival estimator.

Do not treat the 576 correlated events as 576 independent bootstrap units:
the independent statistical units are **12 GitHub Actions runner seeds**.
Repeated episodes on one runner may share host latency, traffic and
implementation biases.

## Frozen comparators from Stage 11

`research.stage12_scale` calls the UNMODIFIED
`research.stage11_hedged.episode` implementation. Fixed/local/
hierarchical/hedged signed-CU, ordinary active through SCP,
consumer passive semantic, NRF-only, equal-budget trusted plain
producer receipt, and full trusted producer-and-consumer monitoring are
all preserved without retuning. The hedged algorithm still alternates
risk-prioritized/fixed two-tick frames, as in the negative Stage 11 result.

No new Data Mining model or active attestation mechanism is being added.

## Scope and security boundaries

Genuine Open5GS NRF and NSSF x2 run, register, and provide native HTTP/2
liveness, but **the selectively altered messages are produced by an
INDEPENDENT RESEARCH NSSF-LIKE COMPONENT and corrupted only by an
INDEPENDENT RESEARCH SCP HTTP/2 proxy**. Actual native Open5GS NF
binaries and 3GPP Nnssf responses remain unmodified. Cryptographic
receipts are from the RESEARCH producer; HMAC CU is from an EXTERNAL
research attestor. This is not native NF internal state attestation,
production SCP exploitation, or evidence of attack against a deployed
operator network. Accurate, misleading, and dynamic risks are deliberately
generated laboratory inputs, not measured 5G NWDAF predictions.

A genuine native-SBI attack, producer/SCP collusion, compromised source
keys and unknown operator attack distribution remain out of scope.

## GitHub reproduction

Workflow: `.github/workflows/stage12-large-sample.yml`.

```bash
python -m pip install -r live/requirements.txt
python -m unittest discover -s stage11_tests -v
python -m unittest discover -s stage12_tests -v
docker compose -f live/compose.yaml -f live/stage5-compose.yaml up -d
python -m research.nrf_probe --retries 45
python -m research.stage12_scale --seed 3601 --output stage12_shard
docker compose -f live/compose.yaml -f live/stage5-compose.yaml down
```

For the full trial, GitHub Actions runs all 12 seeds and aggregates only
when **all** shard jobs pass; any missing, duplicated, or imbalanced
runner, mismatched verification budget, missing tampered transaction
trace, or changed NRF registration causes report failure.

**Interpretation:** A sample 18× larger than Stage 11 reduces estimation
variance for this particular lab distribution. It cannot by itself
establish research novelty, operator-grade robustness or generalization
to a genuinely compromised native 5G SCP.
