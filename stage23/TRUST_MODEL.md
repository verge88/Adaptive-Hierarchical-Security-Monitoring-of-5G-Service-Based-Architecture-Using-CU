# Stage 23 trust-model extension

Stage 23 distinguishes three different claims that must not be conflated.

| Level | Condition | Experimental status |
|---|---|---|
| L1 | false data appears after an otherwise trusted SCP | Stage 21/22 validated |
| L2-SCP-effect | SCP-controlled output may be false and reference bypasses SCP | Stage 22 validated |
| L2-SCP-process | false representation is produced inside open5gs-scpd itself | Stage 23 |
| L2-NRF | NRF itself may be false while an independent witness remains outside NRF control | not yet validated |
| L3 | attacker controls both observation branches or their common truth source | not resolvable by pairwise consistency alone |

For Stage 23, let S denote the native SCP process and N the native NRF.  The
trusted and consumer observations are

    R_t = O_N(X_t)
    C_t = O_S(A_t(O_N(X_t+delta)))

where A_t is the frozen research instrumentation executed inside S.  The
instrumentation is not a network service and cannot be selected by an SBI
message.  It is enabled only in the disposable Stage-23 build.

The monitor receives no private schedule or native-SCP mutation log.  Those
artifacts are joined only after blind detection.

If both R_t and C_t are instead derived from the same false SCP representation,
the pairwise comparison has no truth-bearing discrepancy.  The common-path
negative control preserves that limitation explicitly.

Stage 23 therefore tests placement of the independent witness relative to a
compromised component.  It does not claim that the instrumentation represents
a specific exploit chain or that all possible SCP compromises must alter one of
the frozen monitored representations.
