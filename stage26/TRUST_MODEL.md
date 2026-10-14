# Stage 26 trust-model note

Stage 26 does not introduce a new trust domain. It reuses the Stage-25
NRF-independent witness and isolates a detector-sensitivity question.

Let `P(W)` be the witness-supported projection from NF-side evidence and
`P(N)` the consumer projection returned through the instrumented NRF.

During the persistent phantom episode:

    R_t = P(W)
    C_t = P(N) = P(W) + phantom_profile

for 12 consecutive samples.

The canonical-byte signal therefore has a stable positive direction:

    d_t = (|C_t| - |R_t|) / |R_t| > 0.

No threshold or recurrence is modified. The experiment asks whether repeated
evidence under the already frozen directional recurrence is sufficient to cross
its predeclared threshold.

The common-mode control sets `R_t := C_t`, making `d_t = 0`; its expected
failure separates independent-observer evidence from attack labels.

A successful Stage 26 result demonstrates directional sensitivity to a
persistent NRF-originated false-membership shift. It does not imply that every
NRF compromise must be persistent or that the directional channel alone covers
semantic substitutions.
