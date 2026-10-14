# Stage 34 — external signed collector + relational verifier

Stage 33 moved the detector decision outside GitHub, but the telemetry itself was
still created by a GitHub-hosted capture job and the final invariant reduced the
state to two counters.

Stage 34 addresses both limitations in one held-out experiment.

## External telemetry origin

The Open5GS laboratory testbed itself now runs inside the external collector
service:

- native Open5GS v2.7.6 NRF;
- native Open5GS v2.7.6 SCP;
- two native Open5GS v2.7.6 NSSF processes;
- a native NRF build containing only the Stage-34 research fault hook.

The external collector performs h2c NRF Discovery through the native SCP,
canonicalizes the returned NSSF profiles, and signs the complete telemetry
package before GitHub receives it.

GitHub therefore transports signed telemetry; it does not construct the
observation rows used by the detector.

## Identity-bound relational state

The trusted clean baseline is a mapping

    nfInstanceId -> {
        nfType,
        nfStatus,
        fqdn,
        ipv4Addresses,
        nfServices
    }

with duplicate-identity detection.

The relational verifier compares each observed mapping to the frozen external
clean baseline. It preserves which attributes belong to which NF identity rather
than reducing all profile values to a multiset.

## Count-preserving adversarial set

Every Stage-34 mutation preserves both:

    NSSF profile count == 2
    REGISTERED NSSF count == 2

The four preregistered native-NRF response mutations are:

- identity swap between two genuine NSSF profiles;
- replacement of one genuine identity by a phantom identity;
- substitution of one NSSF IPv4 endpoint;
- injection/replacement of an NSSF service relation.

Thus the old Stage-33 count/status rule is intentionally information-free for
these attacks.

## Blind protocol

The external collector generates the private randomized mutation schedule and
returns it as a separate label object.

The external relational verifier receives only:

- the signed telemetry package;
- the collector signature.

It never receives private labels.

The final audit joins labels only after the relational verdict has been signed.

## Freshness and integrity

For every run:

- GitHub creates a fresh random challenge nonce;
- the collector signs that nonce inside its telemetry package;
- the collector includes a monotonically increasing sequence number;
- the verifier rejects repeated nonces;
- the verifier rejects sequence rollback;
- GitHub verifies the collector signature;
- GitHub verifies the verifier signature;
- a modified collector package and a modified verdict must fail signature
  verification;
- an immediate replay of the same signed collector package must be rejected.

The nonce/sequence replay state is process-lifetime software state. It is not a
TPM monotonic counter.

## Held-out design

The preregistered live block uses:

- 32 independent external Open5GS restarts;
- seeds 12001..12032;
- 24 randomized attack episodes per run;
- 768 total count-preserving attack episodes;
- six episodes of each attack family per run;
- balanced short/medium/long duration classes;
- balanced low/medium/high mutation-density classes.

## Primary comparison

The report compares, on the exact same episodes:

1. legacy Stage-33 cardinality/status invariant;
2. identity-bound relational verifier.

The primary outcome is the paired runner-level recall gain on attacks that
preserve the legacy invariants.

## Claim boundary

This stage removes GitHub from both Open5GS telemetry creation and detector
decision for the tested block. The collector and verifier are separate external
services and sign their outputs.

It is still software-separated rather than hardware-attested. Compromise of the
Render control plane, the collector container, or both external services is
outside the validated model.
