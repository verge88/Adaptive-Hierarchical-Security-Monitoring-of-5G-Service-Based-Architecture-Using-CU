# Stage 22 trust-model delta

Stage 22 extends the Stage-21 trust hierarchy with an experimentally testable
SCP-compromise case.

| Level | Assumption | Stage-22 status |
|---|---|---|
| L0 | private labels unavailable to detector | enforced |
| L1 | attacker changes only a post-SCP consumer copy | already validated by Stage 21 |
| L2-SCP | SCP-controlled output may be arbitrarily corrupted while the reference bypasses SCP | implemented for live validation |
| L2-NRF | NRF may be compromised while an independent witness remains outside NRF control | not yet validated |
| L3 | attacker controls both observations or their common source | intentionally undetectable by pairwise consistency alone |

The key Stage-22 invariant is not a second request by itself.  It is placement of
the second observation **outside the compromised component's control domain**.

For L2-SCP the approximate observation model is:

\[
R_t = O_{NRF}(X_t), \qquad
C_t = A^{SCP}_t(O_{SCP\rightarrow NRF}(X_{t+\Delta})).
\]

If the fault changes any frozen monitored representation, then the pair may
produce observable evidence

\[
\phi_k(R_t) \ne \phi_k(C_t).
\]

The common-path control instead forces both observations to share the same
corrupted view.  In that case

\[
\forall k:\phi_k(R_t)=\phi_k(C_t)
\]

and pairwise consistency cannot distinguish coordinated falsehood from truth.

The experiment does not patch or exploit the native Open5GS SCP binary.  It
injects the observable effect at the SCP consumer-facing boundary after genuine
native forwarding.  Results must therefore be described as validation of the
**trust-boundary/effect model**, not as exploitation of a specific SCP
implementation vulnerability.
