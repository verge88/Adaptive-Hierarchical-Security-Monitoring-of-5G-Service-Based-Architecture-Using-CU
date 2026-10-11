"""Stage 21 stable semantic integrity primitives.

Stage 20 deliberately ignored scalar JSON values. Stage 21 adds a separate
semantic channel that compares only warm-up-stable scalar paths. Scalar values
are represented by deterministic SHA-256 equality tokens so detector telemetry
does not need raw values. These digests are NOT claimed to provide privacy
against dictionary attacks; they are only equality-preserving research tokens.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import statistics

DOMAIN = "stage21-semantic-v1|"


def _kind(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return type(value).__name__


def _digest(value) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256((DOMAIN + raw).encode("utf8")).hexdigest()


def semantic_projection(obj) -> dict[str, Counter[str]]:
    """Map normalized typed scalar paths to multisets of value digests.

    List indices are normalized to [] so repeated records are compared as
    multisets at each path. This catches value substitution that changes a
    path's value multiset, while intentionally not preserving cross-field or
    cross-entity relationships.
    """
    output: dict[str, Counter[str]] = {}

    def visit(value, path: str):
        if isinstance(value, dict):
            for key in sorted(value):
                visit(value[key], f"{path}/{key}")
            return
        if isinstance(value, list):
            for item in value:
                visit(item, f"{path}[]")
            return

        key = f"{path}:{_kind(value)}"
        output.setdefault(key, Counter())[_digest(value)] += 1

    visit(obj, "$")
    return output


def serialize_projection(
    projection: dict[str, Counter[str]],
) -> dict[str, dict[str, int]]:
    return {
        path: dict(sorted(counter.items()))
        for path, counter in sorted(projection.items())
    }


def deserialize_projection(
    data: dict[str, dict[str, int]],
) -> dict[str, Counter[str]]:
    return {
        str(path): Counter(
            {str(digest): int(count) for digest, count in values.items()}
        )
        for path, values in data.items()
    }


def projection_mismatch(
    trusted: dict[str, Counter[str]],
    consumer: dict[str, Counter[str]],
    selected_paths: tuple[str, ...],
) -> tuple[int, int, tuple[str, ...]]:
    mismatched = []
    token_distance = 0
    for path in selected_paths:
        left = trusted.get(path, Counter())
        right = consumer.get(path, Counter())
        if left != right:
            mismatched.append(path)
            token_distance += sum((left - right).values())
            token_distance += sum((right - left).values())
    return len(mismatched), token_distance, tuple(mismatched)


@dataclass(frozen=True)
class SemanticQuorumConfig:
    paired_agreement_threshold: float
    temporal_stability_threshold: float
    window_ticks: int
    required_hits: int
    min_mismatched_paths: int
    large_mismatched_paths: int
    recovery_clean_ticks: int


class SemanticQuorumState:
    """Finite-memory semantic mismatch detector gated by warm-up stability."""

    def __init__(
        self,
        warmup_pairs: list[
            tuple[
                dict[str, Counter[str]],
                dict[str, Counter[str]],
            ]
        ],
        config: SemanticQuorumConfig,
    ):
        if not warmup_pairs:
            raise ValueError("Warm-up semantic pairs required")
        self.config = config
        trusted_rows = [pair[0] for pair in warmup_pairs]
        consumer_rows = [pair[1] for pair in warmup_pairs]
        all_paths = sorted(
            {
                path
                for row in trusted_rows + consumer_rows
                for path in row
            }
        )

        paired = {}
        temporal = {}
        selected = []
        for path in all_paths:
            paired_fraction = statistics.mean(
                trusted.get(path, Counter())
                == consumer.get(path, Counter())
                for trusted, consumer in warmup_pairs
            )
            paired[path] = paired_fraction

            signatures = [
                tuple(sorted(trusted.get(path, Counter()).items()))
                for trusted in trusted_rows
            ]
            counts = Counter(signatures)
            modal = max(counts.values())
            temporal_fraction = modal / len(signatures)
            temporal[path] = temporal_fraction

            if (
                paired_fraction >= config.paired_agreement_threshold
                and temporal_fraction
                >= config.temporal_stability_threshold
            ):
                selected.append(path)

        self.paired_agreement = paired
        self.temporal_stability = temporal
        self.selected_paths = tuple(selected)
        self.enabled = bool(self.selected_paths)
        self.hit_ages: list[int] = []
        self.recovery_remaining = 0

    def observe(
        self,
        trusted: dict[str, Counter[str]],
        consumer: dict[str, Counter[str]],
    ) -> dict:
        mismatch_count, token_distance, paths = projection_mismatch(
            trusted,
            consumer,
            self.selected_paths,
        )

        # After an alarm, do not let residual attack pulses seed a second
        # quorum that can spill into a clean gap. Recovery ends only after a
        # configured number of exact paired matches in succession.
        if self.recovery_remaining:
            self.hit_ages.clear()
            if mismatch_count == 0:
                self.recovery_remaining -= 1
            else:
                self.recovery_remaining = (
                    self.config.recovery_clean_ticks
                )
            return {
                "enabled": self.enabled,
                "selected_path_count": len(self.selected_paths),
                "mismatched_path_count": mismatch_count,
                "semantic_token_distance": token_distance,
                "mismatched_paths": list(paths),
                "quorum_hits": 0,
                "in_recovery": True,
                "recovery_remaining": self.recovery_remaining,
                "large_alert": False,
                "quorum_alert": False,
                "alert": False,
            }

        self.hit_ages = [
            age + 1
            for age in self.hit_ages
            if age + 1 < self.config.window_ticks
        ]
        qualifies = (
            self.enabled
            and mismatch_count >= self.config.min_mismatched_paths
        )
        if qualifies:
            self.hit_ages.append(0)

        large_alert = (
            self.enabled
            and mismatch_count
            >= self.config.large_mismatched_paths
        )
        quorum_alert = (
            qualifies
            and len(self.hit_ages) >= self.config.required_hits
        )
        alert = large_alert or quorum_alert

        result = {
            "enabled": self.enabled,
            "selected_path_count": len(self.selected_paths),
            "mismatched_path_count": mismatch_count,
            "semantic_token_distance": token_distance,
            "mismatched_paths": list(paths),
            "quorum_hits": len(self.hit_ages),
            "in_recovery": False,
            "recovery_remaining": 0,
            "large_alert": large_alert,
            "quorum_alert": quorum_alert,
            "alert": alert,
        }
        if alert:
            self.hit_ages.clear()
            self.recovery_remaining = self.config.recovery_clean_ticks
        return result


SEMANTIC_GRID = tuple(
    SemanticQuorumConfig(
        paired_agreement_threshold=paired,
        temporal_stability_threshold=temporal,
        window_ticks=window,
        required_hits=hits,
        min_mismatched_paths=1,
        large_mismatched_paths=large,
        recovery_clean_ticks=recovery,
    )
    for paired in (0.98, 1.00)
    for temporal in (0.90, 0.95, 1.00)
    for window in (8, 12, 16)
    for hits in (2, 3, 4)
    for large in (3, 5)
    for recovery in (2, 3)
)
