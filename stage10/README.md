# Stage 10 — selective dynamic lab-SCP message alteration with producer-bound receipts

**Strict source/threat boundary.** The disposable lab starts genuine native
Open5GS NRF, AUSF and two NSSF processes. Native NF code, native SBI messages,
actual NF registrations and any real SCP are NOT compromised. A separate
RESEARCH dynamic NSSF-like HTTP/2 producer and RESEARCH SCP relay enable
repeatable selective corruption of research consumer-facing replies.
This is evidence about a *model of* selective intermediary tampering,
not demonstrated compromise of a commercial or native Open5GS SCP.

## Proposed scientific mechanism

The producer returns a plausible dynamic choice of one of two legal slices
and a fresh transaction ID, request hash and nonce. Producer records
{transaction ID, request hash, response hash, context}, authenticated with
an independent producer-only HMAC key. A lab SCP forwards the reply; only
during a controlled episode it changes the consumer copy of the chosen slice
for one context, either to the alternative legal slice or the previously
selected slice. The rest of the response remains plausible and NRF registration
stays unchanged. The original producer receipt is obtained through a
separate independent trusted path that does not pass through the SCP.

An external research CU agent challenges this trusted record with a fresh
nonce, signed consumer request and response, and independently validates
the producer HMAC. This agent does NOT attest the internal state of actual
native Open5GS NF binaries. If producer keys or the attestor are compromised,
the protocol cannot guarantee integrity.

## Fair and adverse controls

- Native NRF-only registration watcher: expected zero detections.
- Strong passive SEMANTIC consumer monitor: reads all consumer replies and
  verifies all PUBLIC invariants, but never sees private producer decisions.
- Ordinary active HTTP/2 test: two fresh transaction requests per tick
  sent through the same potentially corrupt SCP, but no trusted origin proof.
- Trusted plain-direct origin: TWO original consumer transaction hashes per
  tick fetched directly via a trusted channel, NO CU-HMAC wrapper.
- Fixed, local, hierarchical signed CU: TWO original consumer transaction
  proofs per tick, matching the trusted plain-direct budget.
- STRONG full two-sided comparator: trusted original hash for ALL FOUR
  consumer transactions per tick; doubled proof budget, intentionally
  stronger baseline. The budget and trust differences are disclosed.

No detector gets attack ground-truth labels or faulted NF indices; labels
are available only to the injector/evaluator. Within each tick, comparator
execution order is shuffled using a seed independent of the attack label.
The default active budget is two transactions per 210 ms scheduling tick
(46 proof checks/episode); full two-sided is four checks/tick (92).
CU-local and CU-hierarchy additionally enforce a 3-tick maximum probe gap.

## Risk alignment ablation

A benign publicly visible research load proxy is biased toward one zone.
Half of episodes attack a matching zone (aligned); half attack the opposite
zone (anti-aligned). This is **synthetic** and not operator data or novel
machine learning. Per runner: 2 tamper types × 2 alignment types × 2 reps.
Four runner shards (seeds 3101-3104) test 32 independent lab episodes,
with runner-level bootstrap and exact two-sided sign-test checks.

## Reproduce

GitHub Actions workflow `.github/workflows/stage10-scp-integrity.yml`
starts native Open5GS, runs Python HTTP/2 tests, exercises lab SCP faults,
records full proxy tamper transaction IDs and NF registration/liveness,
then compares all controls.

Locally (requires Python 3.12 and Docker Compose):

    python -m pip install -r live/requirements.txt
    python -m unittest discover -s stage10_tests -v
    docker compose -f live/compose.yaml -f live/stage5-compose.yaml up -d
    python -m research.nrf_probe --retries 45
    python -m research.stage10_scp --seed 3101 --output stage10_shard
    docker compose -f live/compose.yaml -f live/stage5-compose.yaml down

## Interpretation

Expected extra detection capability of origin-bound CU versus consumer-only
monitoring comes from PRIVILEGED PRODUCER TRUST information, not guaranteed
scientific innovation of the CU control information unit. A trusted direct
producer comparison or complete endpoint-to-endpoint integrity audit can
match or outperform CU. A genuine contribution in scheduling requires
a seed-stable, neutral/misleading-risk-robust improvement at equal checking
budget over fixed/local and strong trusted plain-direct comparators.

Do not claim this experiment tests hardware attestation, actual malicious
native NSSF behavior, real 3GPP SCP compromise, authenticated SBI end-to-end
standard interoperability, NF-SCP collusion or existing patent priority.
