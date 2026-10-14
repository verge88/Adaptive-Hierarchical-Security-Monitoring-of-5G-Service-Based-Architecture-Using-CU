# Stage 24 trust-model extension

Stage 24 separates NRF compromise from the common-source limitation.

| Level | Condition | Status |
|---|---|---|
| L2-SCP-process | false representation produced inside native SCP; external reference bypasses SCP | validated by Stage 23 |
| L2-NRF-process | false NF Discovery representation produced inside native NRF; monitored semantic facts reconstructed from NF-side evidence | Stage 24 |
| L3-common-source | attacker controls NRF and every external witness used to reconstruct the monitored facts | not resolvable by pairwise consistency alone |

Let `N` be the NRF process, `F_i` the two native NSSF processes, and
`W(F_1,F_2)` the external witness constructed from each NSSF's own registered
state record plus direct SBI liveness.

For the Stage-24 semantic channel:

    R_t = phi_sem(W(F_1, F_2))
    C_t = phi_sem(SCP(N(X_t)))

where the controlled malicious transformation is executed inside `N` before
the NRF response is sent.

The witness intentionally contains only semantic facts independently justified
outside the NRF process.  It does not synthesize unobserved service metadata.

Numeric byte and structural channels are neutralized in Stage 24.  Therefore
the Stage-24 result must not be generalized to independent NRF truth for every
channel of the full detector.

The common-mode control sets the semantic reference equal to the compromised
NRF view.  Its expected failure is a required negative control, demonstrating
that an independent witness, rather than merely a second observation, is the
source of detection evidence.
