# Stage 33 — final independent external-verifier iteration

Stage 32 moved key custody and policy approval outside GitHub, but the final
verification and detector decision still executed on GitHub-hosted runners.

Stage 33 moves the **decision itself** into a separately administered Render
web service. The service is deployed with auto-deploy disabled, stores its
private signing key only in the Render environment, and independently
recomputes the Stage-29 invariant from raw label-free telemetry.

## Experimental question

Does the detector result remain reproducible when GitHub performs only live
Open5GS capture, while an external execution domain performs the security
decision and signs the result?

## External verifier

The external service receives only:

- deterministic Stage-33 policy SHA-256;
- a fresh request nonce;
- raw label-free telemetry.

It never receives attack labels.

The service independently checks:

- the approved policy digest;
- contiguous observation ticks;
- the expected Stage-30 epoch for each tick;
- consumer/witness equality for the common-source negative control;
- the preregistered legitimate transition interval;
- the discrete NSSF cardinality and REGISTERED cardinality.

It then computes:

    external_invariant_alert =
        consumer_nssf_count != expected_nssf_count
        OR consumer_registered_count != expected_registered_count

The verdict is bound to the complete request SHA-256 and signed with an ECDSA
P-256 private key held only by Render.

## Isolation controls

- Render auto-deploy is disabled.
- The external private key is never committed to GitHub and is never delivered
  to a GitHub Actions runner.
- GitHub pins the external public-key SHA-256.
- The external service pins one approved deterministic policy digest.
- The client verifies the signed request digest and verdict.
- A locally modified verdict must fail signature verification.
- Private attack labels are joined only after all external decisions finish.

## Held-out block

Fresh runners are **10001..10008**.

The Stage-28 randomized attack generator, Stage-30 legitimate transitions, and
Stage-29 invariant semantics remain frozen.

## Remaining boundary

Stage 33 removes GitHub from the detector-decision and signing-key-custody path
for this experiment, but raw telemetry is still captured on GitHub-hosted
runners. A malicious capture layer could fabricate observations before the
external verifier sees them.

A stronger future system would originate telemetry from attested collectors or
have the external domain receive measurements directly from the monitored
network.
