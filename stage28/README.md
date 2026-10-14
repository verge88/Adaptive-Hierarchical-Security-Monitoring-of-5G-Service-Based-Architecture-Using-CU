# Stage 28 — randomized common-source robustness stress

Stage 27 deliberately used a strong 12-of-12 persistent phantom-profile
episode. That was appropriate for proving the L3/common-source boundary, but it
also made the attested and false states easy to separate.

Stage 28 keeps the trust mechanism and detector frozen while making the attack
distribution substantially harder and private.

## Research question

Does Stage-27 recovery survive when attack timing and strength vary, rather than
using the same deterministic persistent pattern on every runner?

## Frozen elements

Stage 28 does **not** change:

- the Stage-21 detector thresholds, windows, recovery logic, or channel fusion;
- the Stage-27 software-rooted authority model;
- the signed NSSF baseline: two logical NSSF instances, both REGISTERED;
- the common-source failure model: the compromised witness mirrors the
  compromised NRF consumer state.

The authority still signs a canonical manifest with an ephemeral Ed25519 key.
The private key is deleted and never uploaded.

## Randomized private attack distribution

Every runner independently realizes twelve episodes. The exact plan is generated
with system randomness and stored only with private labels.

The preregistered distribution is:

- four short episodes: 2–4 samples;
- four medium episodes: 5–8 samples;
- four long episodes: 9–14 samples;
- four low-density episodes;
- four medium-density episodes;
- four high-density episodes;
- four episodes from each mutation family:
  - `phantom_registered`;
  - `phantom_suspended`;
  - `status_substitution`;
- phantom multiplicity is one or two;
- clean inter-episode gaps are 5–9 samples.

For intermittent episodes only a private subset of ticks is actually mutated.
The realized mutation density, duration, family and exact tick positions are
unavailable to verifier and blind-detector jobs.

## Native NRF implementation

The Open5GS v2.7.6 NRF is built with a research-only hook inside
`nrf_nnrf_handle_nf_discover()`.

The hook reads a local file:

    /run/stage28/plan.tsv

after a local enable marker is created. There is no network control surface.
Each plan entry contains a successful Discovery tick, mutation family and
multiplicity.

The internal NRF registry is not modified; only the outgoing Discovery response
is changed.

## Why this experiment is more informative than Stage 27

Stage 27 event recall was 1.000 because all 48 attack episodes were long and
persistent enough that every channel had time to accumulate evidence.

Stage 28 reports more than event recall:

- detected episodes / total randomized episodes;
- Wilson 95% interval for finite-block recall;
- mutation-tick alert coverage;
- attack-window alert fraction;
- mean horizon-penalized delay;
- false alarms per 1000 clean samples;
- combined recall stratified by attack family;
- combined recall stratified by duration bin;
- combined recall stratified by density bin.

Therefore, even if event recall again equals 1.000, the report still exposes how
much of each attack was actually covered by alarms and the finite-sample
uncertainty remains non-degenerate.

## Blind protocol

Preregistered runner identifiers are **9501..9508**.

The realized private schedule and the native-NRF mutation log are uploaded only
with private labels. The attestation verifier receives only raw, label-free
telemetry plus the signed authority material. The blind detector receives only
verified projected telemetry.

Labels are joined only after all blind jobs finish.

## Claim boundary

Stage 28 remains a software-rooted GitHub Actions experiment. It does not claim
TPM/TEE remote attestation or resilience to compromise of the authority job or
GitHub Actions control plane.

A positive result supports robustness of the Stage-27 trust-domain recovery
against a broader randomized family of attack durations, densities and
semantics. It does not imply universal 100% detection outside the sampled
distribution.
