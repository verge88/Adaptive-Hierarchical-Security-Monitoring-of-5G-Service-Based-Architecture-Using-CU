"""EDF-feasible risk scheduler with a hard service-gap bound.

A check occupies one slot; B independent CU checks can be sent per tick.
At every tick the algorithm selects the highest-risk *feasible* batch:
all other NFs must remain schedulable by their individual deadlines.
If the bound is infeasible for N, B and gap, the constructor fails.
No attack labels or event ground truth are used for scheduling.
"""
from __future__ import annotations
from itertools import combinations

def bounded_choose(tick, local, spatial, previous, *, warmup_end=12, budget=2, max_gap=4):
    size = len(previous)
    if not size or len(local) != size or len(spatial) != size:
        raise ValueError("Feature lengths must match NF count")
    if budget <= 0 or budget > size or max_gap*budget < size:
        raise ValueError("Deadline infeasible: insufficient CU budget")
    # Nodes not yet challenged have a virtual previous check at warmup_end-1.
    last = [v if v >= warmup_end else warmup_end-1 for v in previous]
    scores = [
        .45*local[i] + 1.45*spatial[i] + .23*min(20, max(0,tick-last[i]))
        for i in range(size)
    ]
    viable = []
    for batch in combinations(range(size), budget):
        deadlines = sorted(last[i]+max_gap for i in range(size) if i not in batch)
        # After spending the current batch, earliest slots are tick+1;
        # EDF provides a necessary and sufficient feasibility test for
        # independent, one-slot checks with these deadlines.
        if all(d >= tick + 1 + j//budget for j,d in enumerate(deadlines)):
            viable.append(batch)
    if not viable:
        raise RuntimeError("No feasible CU batch: scheduler deadline invariant violated")
    return list(max(viable, key=lambda xs: (
        sum(scores[i] for i in xs), tuple(-i for i in xs))))
