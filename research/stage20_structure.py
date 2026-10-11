"""Stage 20 structural integrity primitives.

The structural representation deliberately excludes scalar values. It records
only typed JSON paths and their multiplicities, making it insensitive to normal
value churn while exposing field deletion/addition and profile multiplicity
changes.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


def structural_counter(obj) -> Counter[str]:
    tokens: Counter[str] = Counter()

    def visit(value, path: str):
        if isinstance(value, dict):
            tokens[f"{path}:object"] += 1
            for key in sorted(value):
                child = f"{path}/{key}"
                tokens[f"{child}:field"] += 1
                visit(value[key], child)
            return

        if isinstance(value, list):
            tokens[f"{path}:array"] += 1
            for item in value:
                visit(item, f"{path}[]")
            return

        if value is None:
            kind = "null"
        elif isinstance(value, bool):
            kind = "bool"
        elif isinstance(value, (int, float)):
            kind = "number"
        elif isinstance(value, str):
            kind = "string"
        else:
            kind = type(value).__name__
        tokens[f"{path}:{kind}"] += 1

    visit(obj, "$")
    return tokens


def serialize_counter(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items()))


def deserialize_counter(data: dict[str, int]) -> Counter[str]:
    return Counter({str(key): int(value) for key, value in data.items()})


@dataclass(frozen=True)
class StructuralDifference:
    missing_tokens: int
    extra_tokens: int
    total_tokens: int
    normalized_distance: float

    @property
    def exact_match(self) -> bool:
        return self.total_tokens == 0

    @property
    def direction(self) -> int:
        if self.extra_tokens > self.missing_tokens:
            return 1
        if self.missing_tokens > self.extra_tokens:
            return -1
        return 0


def structural_difference(
    trusted: Counter[str],
    consumer: Counter[str],
) -> StructuralDifference:
    missing = trusted - consumer
    extra = consumer - trusted
    missing_tokens = sum(missing.values())
    extra_tokens = sum(extra.values())
    denominator = max(
        1,
        sum(trusted.values()),
        sum(consumer.values()),
    )
    total = missing_tokens + extra_tokens
    return StructuralDifference(
        missing_tokens=missing_tokens,
        extra_tokens=extra_tokens,
        total_tokens=total,
        normalized_distance=total / denominator,
    )


@dataclass(frozen=True)
class StructuralQuorumConfig:
    stability_fraction_threshold: float
    window_ticks: int
    required_hits: int
    min_token_difference: int
    large_difference_tokens: int


class StructuralQuorumState:
    """Warm-up-gated directional structural mismatch memory."""

    def __init__(
        self,
        warmup_differences: list[StructuralDifference],
        config: StructuralQuorumConfig,
    ):
        if not warmup_differences:
            raise ValueError("Warm-up structural differences required")
        self.config = config
        self.exact_fraction = sum(
            item.exact_match for item in warmup_differences
        ) / len(warmup_differences)
        self.enabled = (
            self.exact_fraction
            >= config.stability_fraction_threshold
        )
        self.positive_ages: list[int] = []
        self.negative_ages: list[int] = []

    def observe(self, diff: StructuralDifference) -> dict:
        self.positive_ages = [
            age + 1
            for age in self.positive_ages
            if age + 1 < self.config.window_ticks
        ]
        self.negative_ages = [
            age + 1
            for age in self.negative_ages
            if age + 1 < self.config.window_ticks
        ]

        qualifies = (
            self.enabled
            and diff.total_tokens
            >= self.config.min_token_difference
        )
        if qualifies and diff.direction > 0:
            self.positive_ages.append(0)
        elif qualifies and diff.direction < 0:
            self.negative_ages.append(0)

        large_alert = (
            self.enabled
            and diff.total_tokens
            >= self.config.large_difference_tokens
            and diff.direction != 0
        )
        quorum_alert = (
            self.enabled
            and (
                (
                    diff.direction > 0
                    and len(self.positive_ages)
                    >= self.config.required_hits
                )
                or (
                    diff.direction < 0
                    and len(self.negative_ages)
                    >= self.config.required_hits
                )
            )
        )
        alert = large_alert or quorum_alert

        result = {
            "enabled": self.enabled,
            "exact_fraction": self.exact_fraction,
            "missing_tokens": diff.missing_tokens,
            "extra_tokens": diff.extra_tokens,
            "total_tokens": diff.total_tokens,
            "normalized_distance": diff.normalized_distance,
            "direction": diff.direction,
            "positive_quorum_hits": len(self.positive_ages),
            "negative_quorum_hits": len(self.negative_ages),
            "large_alert": large_alert,
            "quorum_alert": quorum_alert,
            "alert": alert,
        }

        if alert:
            self.positive_ages.clear()
            self.negative_ages.clear()

        return result


STRUCTURAL_GRID = tuple(
    StructuralQuorumConfig(
        stability_fraction_threshold=stability,
        window_ticks=window,
        required_hits=hits,
        min_token_difference=min_diff,
        large_difference_tokens=large,
    )
    for stability in (0.90, 0.95, 0.98, 1.00)
    for window in (12, 16, 20)
    for hits in (2, 3)
    for min_diff in (1, 2)
    for large in (4, 6, 8)
)
