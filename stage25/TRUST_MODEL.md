# Stage 25 trust-model extension

Stage 25 resolves the remaining channel-level limitation of Stage 24 by
separating **source independence** from **schema completeness**.

Let `F_1,F_2` be the native NSSF processes, `N` the potentially compromised
native NRF, `S` the stock SCP, and `P` a common projection restricted to
facts justified outside `N`.

The trusted representation is

    R_t = P(W(F_1,F_2))

where `W` uses NSSF-local registered-state evidence and direct NSSF SBI
liveness.

The consumer representation is

    C_t = P(S(N(X_t)))

where the controlled malicious transformation is executed inside `N`.

The same projection `P` is applied to both sides before any frozen detector
feature is calculated.

| Frozen mechanism | NRF-independent Stage-25 input |
|---|---|
| directional numeric | canonical byte length of P(.) |
| sparse directional | canonical byte discrepancy of P(.) |
| structural | value-free structure of P(.) |
| semantic | stable scalar values of P(.) |

The projection contains only NSSF `nfInstanceId`, `nfType`, `nfStatus`, and the derived `nfRegisteredAtSource` membership fact. Consequently Stage 25 proves independence for all detector
channels **on that monitored representation**. It does not extend the witness
to service endpoints, priorities, load metadata, PLMN attributes, or other NRF
fields that are not independently reconstructed.

A common-mode control sets

    R_t := C_t

for every projected feature. Its expected failure is part of the experiment:
pairwise consistency cannot establish truth when both observations are inside
the same attacker's control domain.

The next trust boundary beyond Stage 25 is not another detector channel. It is
witness compromise itself: if the NRF attacker also controls the NF-side
evidence sources used by `W`, an additional independent trust domain or
cryptographic attestation mechanism is required.
