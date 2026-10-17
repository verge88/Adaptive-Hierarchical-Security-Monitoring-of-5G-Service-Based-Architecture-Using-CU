# Stage 39 — causal online KIE validation with persistent NRF registry poisoning

Stage 39 is a new validation architecture intended to remove the principal
validity threats identified after Stage 38.  It does **not** use a clean NRF
response as an oracle and it does **not** use a post-transition reference in a
decision about an earlier observation.

## Frozen scientific questions

1. Can persistent poisoning of an NRF registry be detected when the NRF itself
   returns the poisoned state consistently?
2. Does a challenge-response runtime witness add information beyond a
   declarative desired-state comparator?
3. Can legitimate lifecycle churn be tolerated online without revealing future
   lifecycle state to the detector?
4. What is the measured attack-to-alarm latency?
5. Does the same invariant detect the registration-poisoning defect class of
   free5GC CVE-2026-55068?

## Trust/data separation

The three sources of evidence are deliberately different:

* **NRF observation** — the state being checked.  It is never used as a source
  of truth.
* **Signed desired state** — immutable deployment constraints fixed before the
  held-out block.  It defines NF role, permitted service set, image/config
  identity and permitted network ranges, but intentionally does not prescribe
  a runtime UUID and may permit an address range.
* **KIE runtime witness** — a host-side process outside the NF containers.  For
  a verifier-issued one-time challenge it inspects container identity, image,
  configuration hash, runtime UUID record, network address and live listening
  socket, then signs the response.  It does not query NRF.

The attacker process receives none of the private signing keys and does not
receive detector decisions while constructing an attack.

## Causal rule

At time t the verifier may use only:

* the desired-state manifest signed before the experiment;
* lifecycle events with timestamps <= t and a valid orchestrator signature;
* a fresh witness response to the verifier's current one-time challenge;
* the current NRF discovery result.

There is no post-state reference.  During a signed lifecycle event the affected
slot may be absent.  If it is present, its runtime-specific attributes must
match the *current* witness response.  All stable slots must match immediately.

## Persistent poisoning

The attack injector sends a real HTTP/2 Nnrf_NFManagement

    PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}

to the unmodified Open5GS NRF.  The forged profile therefore enters the NRF
registration state before it is returned by NF discovery.  The Stage 38
discovery-response mutation hook is not used.

Families include runtime UUID replacement, profile address substitution, FQDN
poisoning, service-endpoint poisoning, NF-type substitution, fake-profile
injection and compound variants.

## Baselines

The final report compares:

* count/status;
* initial exact snapshot (diagnostic weak baseline only);
* signed desired-state reconciliation without runtime witness;
* runtime witness without NRF relational comparison;
* causal relational + KIE witness (proposed method).

The weak baselines are not used as the sole evidence of advantage.

## Background dynamics

A separate lifecycle controller, not the attack generator, creates legitimate
stop/start/restart events.  The verifier learns each event only when it occurs.
The final workflow additionally runs a long benign churn/soak interval with
heartbeats, restarts, scale-like absence/presence intervals and asynchronous
polling.

Development/smoke attack families are disjoint from at least part of the final
held-out family set; fresh seeds alone are not presented as distributional
independence.

## CVE track

A separate GitHub Actions job starts a vulnerable free5GC NRF release and sends
the registration pattern described by CVE-2026-55068.  Success requires the
forged profile to persist and to be returned by NFDiscover; the Stage 39
detector must reject the registry state without consulting a clean NRF copy.

## Scope

This remains a laboratory experiment.  It is designed to test causal integrity
checking and independent evidence, not to claim detection of every possible
5G Core compromise or production readiness.
