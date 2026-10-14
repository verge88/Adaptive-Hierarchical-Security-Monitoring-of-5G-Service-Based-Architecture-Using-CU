# Stage 30 trust and freshness model

## Motivation

Stage 29 uses an immediate invariant mismatch only when the reference is a
verified attestation baseline. That makes baseline freshness part of the
security argument.

A valid signature over a stale state is still a valid signature.

Stage 30 therefore separates:

    authenticity of a baseline
    from
    freshness of a baseline.

## Epoch model

Let B_e be baseline epoch e.

Each signed epoch contains

    e
    valid_from_tick
    valid_until_tick
    expected_state
    H(B_{e-1})

and is signed by the software authority.

The verifier accepts B_e at observation t only if:

    Verify(pk_A, B_e, sigma_e) = true
    valid_from_tick <= t <= valid_until_tick
    epoch chain is contiguous
    previous-manifest hash is correct

The validity windows are non-overlapping and contiguous, so exactly one
baseline is valid for each experimental observation tick.

## Legitimate transition schedule

The authorized logical sequence is:

    epoch 0: two REGISTERED NSSF
    epoch 1: one REGISTERED NSSF after nssf2 deregistration
    epoch 2: two REGISTERED NSSF after nssf2 registration
    epoch 3: two REGISTERED NSSF after nssf restart

The capture runner executes the live Open5GS operation before collecting the
first observation of the new epoch and waits until NRF Discovery reaches the
signed expected state.

## Replay model

At each epoch transition the verifier also evaluates the immediately previous
signed epoch as a stale replay candidate.

A final rollback test presents epoch 0 at the epoch-3 boundary.

These are validly signed documents, so signature verification alone would not
distinguish them. They must fail because their signed validity interval no
longer covers the current logical observation tick.

## Attacker boundary

The modeled attacker can still control:

- the native NRF consumer-visible Discovery response through the research-only
  in-process fault hook;
- the ordinary NF-side witness software output.

The attacker does not control:

- the Stage-30 authority job;
- the ephemeral signing key while the authority job runs;
- the verifier;
- the signed epoch chain;
- the blind detector.

## What Stage 30 does not solve

Logical observation ticks are not a hardware-protected notion of time.

If an attacker can roll back the verifier state, control the authority job, or
change the logical clock itself, this software-rooted epoch protocol is not
sufficient.

A stronger production design would require at least one externally anchored
freshness source, such as:

- TPM-backed monotonic state;
- TEE/confidential-VM attestation with nonce;
- KMS/HSM-backed signing identity plus server-side sequence state;
- an external transparency log or append-only authority service.
