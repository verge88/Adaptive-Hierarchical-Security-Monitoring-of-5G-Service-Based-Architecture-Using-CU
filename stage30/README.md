# Stage 30 — signed baseline freshness with legitimate NF transitions

Stage 29 showed that a one-sample mismatch against a verified signed baseline
can recover sensitivity to short and low-density NRF falsification. Its main
remaining limitation was baseline freshness: a legitimate scale/restart/state
change could be mistaken for an attack if the signed baseline were stale.

Stage 30 validates a software-rooted logical freshness protocol on live Open5GS.

## Research question

Can the Stage-29 attested-invariant rule preserve attack recall while avoiding
false alarms across legitimate NSSF deregistration, registration and restart,
provided that the trusted baseline is advanced through a signed monotonic epoch
chain?

## Signed epoch chain

A separate GitHub Actions authority job creates four canonical baseline
manifests and signs all of them with one ephemeral Ed25519 key.

Each manifest contains:

- monotonic epoch number;
- logical validity interval in observation ticks;
- expected NSSF cardinality;
- expected REGISTERED-state cardinality;
- previous-manifest SHA-256;
- Open5GS baseline version;
- NSSF configuration hashes;
- repository/commit/workflow identity.

The chain is:

| Epoch | Valid ticks | Signed expected state | Authorized transition |
|---|---:|---:|---|
| 0 | 0..29 | 2 NSSF / 2 REGISTERED | initial state |
| 1 | 30..39 | 1 / 1 | nssf2 deregistration |
| 2 | 40..44 | 2 / 2 | nssf2 registration |
| 3 | 45.. | 2 / 2 | nssf restart, same logical state |

The private Ed25519 key is deleted in the authority job and is never uploaded.

## Live legitimate transitions

The capture job performs real Docker/Open5GS transitions:

1. at logical tick 30, `nssf2` is stopped gracefully and capture waits until
   NRF Discovery reports one REGISTERED NSSF;
2. at tick 40, `nssf2` is started and capture waits until Discovery returns
   to two REGISTERED NSSF instances;
3. at tick 45, `nssf` is restarted and capture waits until the two-NSSF
   logical state is restored.

During transition polling the Stage-28 research-only NRF mutation hook is
disabled. Therefore polling does not advance the private attack-plan counter.

## Randomized attacks remain blind

The Stage-28 randomized attack distribution is unchanged, but every private
attack tick is shifted by +20. Consequently no attack mutation occurs before
tick 50 and ticks 30..49 form a clean legitimate-transition validation region.

Eight fresh runners use identifiers **9701..9708**. Every runner receives a
new system-random private attack plan.

The exact attack schedule and native-NRF mutation log remain unavailable to the
authority, freshness verifier, and blind detector.

## Freshness verifier

The verifier:

1. verifies every Ed25519 signature;
2. verifies repository/config identity;
3. checks contiguous monotonic epoch numbers;
4. verifies the previous-manifest hash chain;
5. checks non-overlapping contiguous validity windows;
6. selects exactly one signed baseline for every observation tick;
7. rejects a baseline outside its signed validity interval.

A replay audit deliberately presents the previous signed epoch at each
transition and also attempts a multi-epoch rollback. Any accepted stale baseline
fails the experiment.

## Detector discipline

Stage 30 introduces **no new detector rule**.

It freezes the Stage-29 decision:

    augmented_alert =
        frozen_stage21_combined_alert
        OR verified_attested_invariant_mismatch

Only the trusted baseline supplied to that rule becomes epoch-aware.

## Primary metrics

The audit reports:

- attack event recall and Wilson 95% interval;
- delay and mutation-tick coverage;
- clean false alarms;
- false alarms specifically on legitimate transition ticks;
- stale/replay acceptance count and rate;
- common-source NRF+witness negative control;
- attack-family stratification.

## Claim boundary

Stage 30 is a software-rooted logical freshness experiment.

It does **not** provide:

- a trusted wall clock;
- TPM/TEE measured boot;
- hardware-backed monotonic counters;
- resilience to compromise of the GitHub Actions authority/control plane;
- an automatic production policy for arbitrary unscheduled NF scaling.

A positive result supports the narrower claim that a signed monotonic baseline
epoch protocol can prevent a static attestation baseline from turning the
tested legitimate Open5GS NSSF transitions into false alarms while retaining
detection against the tested NRF falsification distribution.
