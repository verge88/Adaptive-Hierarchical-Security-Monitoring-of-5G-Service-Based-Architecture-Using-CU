# Stage 17 — drift-adaptive e-Page detector

Stage 16 showed that the frozen Stage-15 hierarchical e-CUSUM did not retain
its advantage under distribution shift: a tuned Page-Hinkley detector achieved
higher OOD recall, lower horizon-penalized delay, and fewer false alarms.

Stage 17 is a new detector iteration developed under a stricter protocol.

## Detector idea

The proposed **drift-adaptive e-Page** detector combines two mechanisms:

1. **Integrity e-evidence.** The CU/SCP-vs-NF integrity discrepancy and
   hierarchical corroboration are converted to the same conformal-style
   p-values and power-betting e-values used in Stage 15.
2. **Adaptive Page-Hinkley centering.** The detector operates on log e-evidence
   relative to an online per-NF clean reference. The reference is updated with
   an exponentially weighted, winsorized observation so gradual clean drift can
   be followed without allowing a large attack observation to immediately
   poison the baseline.

The detector therefore does not require two consecutive integrity-tail samples,
which was a recall bottleneck for sparse and micro attacks in Stage 16.

No exact anytime-valid e-process guarantee is claimed because the traffic is
temporally dependent and the reference is adapted online.

## Fair comparator

Page-Hinkley is tuned on the **same development worlds** as the hybrid. The
hybrid must therefore beat a development-tuned Page-Hinkley, not merely the
Stage-16 frozen parameter setting.

Both detectors use the same:
- warm-up interval;
- calibrated integrity and hierarchical features;
- fixed four-CU-per-five-second schedule;
- probe budget;
- attack-label-free observations.

## Data separation

The following seed blocks are fixed before final evaluation:

- Stage-16 historical evaluation, forbidden for Stage-17 development:
  **5001..5200**.
- Stage-17 development/tuning: **6001..6040**.
- Stage-17 final untouched evaluation: **7001..7200**.

The development code explicitly rejects attempts to use either the historical
Stage-16 evaluation block or the Stage-17 final block.

## Development selection rule

For both drift-adaptive e-Page and Page-Hinkley:

1. mean false alarms must be <= **0.50 / 1000 clean checks**;
2. maximize primary OOD event recall;
3. minimize horizon-penalized delay;
4. minimize false alarms.

The final evaluation block is not run by the development workflow.

## Final gate

After development finishes, the selected hybrid and Page-Hinkley configurations
will be frozen in code. Only then will a separate workflow be added to execute
the single final comparison on seeds **7001..7200**.

Success requires the frozen hybrid to improve the primary event-level tradeoff
against the frozen development-tuned Page-Hinkley without exceeding the same
false-alarm ceiling. A negative final result will be retained as such rather
than retuned on final seeds.
