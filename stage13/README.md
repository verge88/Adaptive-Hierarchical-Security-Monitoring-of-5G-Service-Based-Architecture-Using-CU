# Stage 13 — Confidence-calibrated CU: authenticated feedback with frozen independent holdout

**Pre-registered test, not a posthoc fit to Stage12.** Stage12 demonstrated
that a naïve hedged scheduler worsened worst-regime detection latency. Stage13
tests a new conservative model that learns how much to trust synthetic
risk signals **only from previous independently authenticated producer/SCP
discrepancies**, then freezes that model before a disjoint test.

## Exact design and budgets

| Quantity | Before execution |
|---|---:|
| Independent hosted runner seeds | 4801–4812 (12) |
| Calibration incidents per runner | 16 |
| Independent held-out incidents per runner | 24 |
| Total CALIBRATION LAB attacks | 192 |
| Total HELD-OUT LAB attacks | 288 |
| Combined LAB attack injections | 480 |
| Methods including strong baselines | 10 |
| Held-out detector records | 2,880 |
| Calibrated detector records (not in test result) | 1,920 |
| Probe budget: ordinary active, direct-origin, all KIE | 2 per tick × 23 = 46 |
| Full two-ended trusted-control budget | 4 per tick × 23 = 92 |

The calibration phase contains two repeats for each **2 attack types × 4
risk modes**; heldout contains three repeats in each cell. Attack onset
phase is separately randomized. All independent runner seeds use disjoint
episode IDs/transaction IDs between training and test.

**True security boundary:** Actual Open5GS NRF and two native NSSFs are
running/registered/reachable, but the transacted producer and corrupting
SCP are separate, controlled RESEARCH HTTP/2 services, NOT native NSSF
or production SCP. All signatures are LAB producer HMAC and external
LAB agent HMAC, not a proof of native NF internal integrity.

## Confidence gate

The confidence model is updated only after the **signed research CU**
verifies that the ORIGINAL producer response hash disagrees with the
consumer's current message hash; a mismatch identifies the affected
producer context without using the injector's hidden attack label.
Count no more than the FIRST authentically proven corruption per
calibration episode. Relate its NF zone to the public high-risk zone,
then estimate the conservative binomial reliability lower bound.

Frozen decision rule, declared before any held-out observations:

- At least 8 independently attested *calibration episodes* with a
  valid first mismatch are required.
- Use the hierarchical risk scheduler **only if the one-sided 90% Wilson
  lower confidence bound on high-risk-zone agreement exceeds 0.56**.
- Otherwise, **fall back to exact fixed-round-robin** (not a slower
  manually interleaved hedged schedule).
- Decision is frozen across ALL 24 held-out attack episodes on that
  runner. No online updates within test, and no evaluation ground-truth
  fields are passed into the policy.

This is a confidence-gated **research heuristic**, not a theorem of
online conservative safety or of distribution-free delay domination.
For an attacker who makes risk-indicating evidence unreliable, no
method can deduce the unknown target zone before obtaining some
additional truthful evidence. An overconfident model may still
perform worse after regime shift. With four contexts and two checks
per tick, fixed inspection is a strong benchmark.

## Primary endpoints — declared before testing

Three primary comparisons: HELD-OUT WORST per-runner mean
horizon-penalized wall-clock detection time (max over four risk
conditions) for fixed minus guarded CU, naïve hierarchical minus
guarded CU, and trusted plain origin proof minus guarded CU.
Positive difference = guarded faster, negative = guarded WORSE.

Secondary: pooled detection delay, error across each risk regime,
recall, false alarms, active HTTP2 bytes, check gap≤3, and fraction
of runner models actually authorizing risk. Paired resampling must
bootstrap exactly 12 independent **runner clusters** instead of
incorrectly treating 288 related test attacks as independent.
Exact two-sided paired runner sign tests accompany 95% descriptive
cluster-bootstrap intervals. The three named primary tests require
a multiple-testing correction before strong scientific claims.

The trusted plain baseline sees the SAME original producer proofs
without the CU wrapper at the SAME 46-check budget; full trusted
two-sided comparison uses 92 and is not a same-cost competitor.

## Reproduce

Workflow: `.github/workflows/stage13-confidence-guard.yml`

```bash
python -m pip install -r live/requirements.txt
python -m unittest discover -s stage13_tests -v
docker compose -f live/compose.yaml -f live/stage5-compose.yaml up -d
python -m research.nrf_probe --retries 45
python -m research.stage13_trial --seed 4801 --output stage13_shard
docker compose -f live/compose.yaml -f live/stage5-compose.yaml down
```

CI fails if any of 12 seed shards missing, any true tampered
transaction proof missing, training/test episode IDs overlap,
the calibrated policy sees a held-out feedback event, the posterior
disagrees with original first authenticated proof, any budget
or hard gap inequality is violated, or real NF registration changes.

## Interpretation limitation

This does not train a genuine NWDAF model from 5G operator data,
or validate compromised native SCP. The four risk modes are
deliberately engineered synthetic correlations, including one
misleading signal that may remain indistinguishable from a correct
signal until a cryptographic discrepancy is discovered. The
calibration phase has deliberately randomized risk modes, so a
rational uncertainty gate might refuse risk and choose fixed
inspection. That would demonstrate **a safe fallback in this lab
distribution**, not prove a novel or generally superior algorithm.
