# Stage 11 — Robust scheduling under misleading risk telemetry

**Experimental scope.** This is a controlled laboratory test of monitoring
research NSSF-like HTTP/2 responses selectively altered by a RESEARCH SCP.
Real native Open5GS NRF and NSSF are running and independently checked for
registration and reachability; they do NOT issue or receive the research
SBI choice messages and neither their binaries nor a real SCP are compromised.
The original producer's response hash is authenticated by a research-only
producer HMAC key kept separately from the research SCP. External CU HMAC
authenticates a research agent, not native NF internals.

## Scientific question (distinct from Stage 10)

Previous tests showed an unreliable prior can degrade naive risk-weighted
monitoring. Can an explicitly HEDGED scheduler reduce sensitivity to
misleading telemetry while retaining some gains under useful risk signals?
A stronger baseline is a regular independent trusted producer receipt
with EXACTLY the same 2 tx verification budget per scheduler tick.

The hedged policy:
- Odd/even TICK pair always checks all four NF contexts EXACTLY once;
- On the first tick of every other pair, choose 2 high-risk contexts;
- On alternate pairs use a fixed [0,1] coverage start;
- On second tick check exactly the other two contexts;
- Never sees injected fault labels or the tampered target ID.
Every NF is inspected within a two-tick frame and max probe gap must be
at most 3 scheduler ticks. The policy is a robust HEURISTIC, not a
proven minimax- or regret-optimal algorithm.

## Perturbed risk conditions (8 episodes per independent runner)

Cross two corruption modes (plausible-choice replacement vs stale-choice)
with FOUR explicitly simulated prior regimes:

1. **aligned:** high synthetic risk in the attacked zone;
2. **misleading:** high synthetic risk in the other zone;
3. **neutral:** no meaningful zonal signal, only noise;
4. **switch:** useful high zone early but deliberately flips halfway.

The high-risk labels are deliberately generated as experimental inputs,
not derived from real 5G NWDAF or trained on operator data. This is NOT
evidence of a real NF compromise or trained Data Mining signal. Each
independent runner randomizes target context and event order.

## Strong competitors and budgets

NRF-only; strong consumer-only semantic validation; ordinary active HTTP/2
through the same lab SCP; trusted ORIGINAL-PRODUCER direct confirmation
without HMAC-CU overhead; fixed, local, zonal and HEDGED HMAC-CU at
EXACTLY TWO selected original transactions/tick (46 over 23 ticks);
and strong full two-ended independent producer comparison at FOUR original
transactions/tick (92). The latter has double bandwidth by design and
is an upper-bound control, NOT a budget-matched opponent.

Within-tick algorithm order is independently shuffled. Genuine HTTP/2
status 200 with dynamic plausible responses is not by itself proof of
integrity. Check counts, bytes and monotonic wall-clock alert delays.
The MAIN comparative endpoints are (a) worst CONDITIONAL mean delay across
the four telemetry regimes, (b) latency in misleading and switched prior,
and (c) whether the hedged algorithm beats FIXED / LOCAL / TRUSTED PLAIN
at identical verification cost. Runner-level cluster bootstrap intervals
and exact two-sided sign p values are both reported; just 4 runner
clusters cannot justify a broad statistical significance claim.

## Reproduce

With disposable Docker Open5GS, Python 3.12 and true HTTP/2 dependency:

    python -m pip install -r live/requirements.txt
    python -m unittest discover -s stage11_tests -v
    docker compose -f live/compose.yaml -f live/stage5-compose.yaml up -d
    python -m research.nrf_probe --retries 45
    python -m research.stage11_hedged --seed 3301 --output stage11_shard
    docker compose -f live/compose.yaml -f live/stage5-compose.yaml down

CI: .github/workflows/stage11-hedged-risk.yml
Four independent runner seeds 3301–3304, 32 controlled lab incidents.

## Limits

A warning signal that accurately localizes compromise is privileged
information even if labeled only "risk". The aligned and switch regimes
are controlled hypotheses, NOT independently validated predictive models.
Pooled gain across designer-chosen 25% prior regimes should NOT be taken
as operator-level accuracy. Origin integrity is a research producer
receipt, not authenticated real NSSF SBA provenance. Attack-aware
adaptation and signal poisoning robustness need many more independent
runners and realistic native SBI data; under a truly unknown adversarial
prior, no algorithm can generally beat an optimal omniscient policy.
