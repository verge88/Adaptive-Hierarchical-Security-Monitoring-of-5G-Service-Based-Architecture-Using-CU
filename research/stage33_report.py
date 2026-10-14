"""Stage 33 final audit of the independently executed verifier."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import statistics
from .stage28_report import wilson_interval

EXPECTED_SEEDS = tuple(range(10001, 10009))
TRANSITION_TICKS = set(range(30, 50))

def load_by_seed(root: Path, filename: str) -> dict[int, dict]:
    out = {}
    for path in root.rglob(filename):
        doc = json.loads(path.read_text(encoding="utf8"))
        seed = int(doc["seed"])
        if seed in out:
            raise AssertionError(f"duplicate {filename} for seed {seed}")
        out[seed] = doc
    return out

def score_seed(labels: dict, verdict_doc: dict, provenance: dict) -> dict:
    seed = int(labels["seed"])
    if int(verdict_doc["seed"]) != seed or int(provenance["seed"]) != seed:
        raise AssertionError("Stage33 seed mismatch")
    if int(labels["stage"]) != 33 or int(provenance["stage"]) != 33:
        raise AssertionError("Stage33 stage marker mismatch")
    if labels["stage33_role"] != "held_out_external_verifier_validation":
        raise AssertionError("Stage33 label role mismatch")
    if provenance["stage33_role"] != "held_out_external_verifier_validation":
        raise AssertionError("Stage33 provenance role mismatch")
    if not verdict_doc["signature_verified"]:
        raise AssertionError("external verdict signature not verified")
    if not verdict_doc["tampered_verdict_rejected"]:
        raise AssertionError("tampered external verdict was not rejected")

    verdict = verdict_doc["verdict"]
    alerts = {
        int(row["tick"]) for row in verdict["alerts"]
        if bool(row["external_invariant_alert"])
    }
    common_alerts = {
        int(row["tick"]) for row in verdict["alerts"]
        if bool(row["colluding_pair_alert"])
    }
    if common_alerts:
        raise AssertionError("Stage33 common-source negative control alerted")

    episodes = labels["episodes"]
    attack_window_ticks = {
        tick for ep in episodes
        for tick in range(int(ep["start_tick"]), int(ep["end_tick"]))
    }
    mutation_ticks = {
        int(tick) for ep in episodes for tick in ep["mutation_ticks"]
    }
    total_ticks = int(labels["total_ticks"])
    warmup = int(labels["warmup_ticks"])
    clean_ticks = set(range(warmup, total_ticks)) - attack_window_ticks

    episode_rows = []
    for ep in episodes:
        start = int(ep["start_tick"])
        end = int(ep["end_tick"])
        inside = sorted(t for t in alerts if start <= t < end)
        episode_rows.append({
            "episode": int(ep["episode"]),
            "kind": ep["kind"],
            "duration_bin": ep["duration_bin"],
            "density_bin": ep["density_bin"],
            "detected": bool(inside),
            "delay_ticks": inside[0] - start if inside else end - start,
        })

    detected = sum(int(row["detected"]) for row in episode_rows)
    return {
        "seed": seed,
        "event_detected": detected,
        "event_total": len(episode_rows),
        "event_recall": detected / len(episode_rows),
        "mean_horizon_penalized_delay_ticks": statistics.mean(
            row["delay_ticks"] for row in episode_rows
        ),
        "mutation_tick_alert_coverage": len(alerts & mutation_ticks) / max(1, len(mutation_ticks)),
        "false_alarm_count": len(alerts & clean_ticks),
        "clean_tick_count": len(clean_ticks),
        "false_alarms_per_1000_clean_ticks": 1000 * len(alerts & clean_ticks) / max(1, len(clean_ticks)),
        "legitimate_transition_alert_count": len(alerts & TRANSITION_TICKS),
        "legitimate_transition_tick_count": len(TRANSITION_TICKS),
        "common_source_alert_count": len(common_alerts),
        "policy_sha256": verdict_doc["policy_sha256"],
        "public_key_sha256": verdict_doc["public_key_sha256"],
        "external_service_revision": verdict_doc["external_service_revision"],
        "request_sha256": verdict_doc["request_sha256"],
        "episode_results": episode_rows,
    }

def stratified(rows: list[dict], field: str) -> dict:
    groups: dict[str, list[bool]] = {}
    for row in rows:
        for ep in row["episode_results"]:
            groups.setdefault(str(ep[field]), []).append(bool(ep["detected"]))
    return {
        key: {
            "detected": sum(values),
            "total": len(values),
            "recall": statistics.mean(values),
            "wilson95": wilson_interval(sum(values), len(values)),
        }
        for key, values in sorted(groups.items())
    }

def summarize(rows: list[dict]) -> dict:
    policies = {r["policy_sha256"] for r in rows}
    keys = {r["public_key_sha256"] for r in rows}
    revisions = {r["external_service_revision"] for r in rows}
    requests = {r["request_sha256"] for r in rows}
    if len(policies) != 1 or len(keys) != 1 or len(revisions) != 1:
        raise AssertionError("Stage33 external verifier identity changed across runners")
    if len(requests) != len(rows):
        raise AssertionError("Stage33 request digests are not unique")

    successes = sum(r["event_detected"] for r in rows)
    total = sum(r["event_total"] for r in rows)
    false_alarms = sum(r["false_alarm_count"] for r in rows)
    clean_ticks = sum(r["clean_tick_count"] for r in rows)
    transition_alerts = sum(r["legitimate_transition_alert_count"] for r in rows)
    transition_ticks = sum(r["legitimate_transition_tick_count"] for r in rows)

    return {
        "independent_live_runners": len(rows),
        "seeds": [r["seed"] for r in rows],
        "total_attack_episodes": total,
        "event_detected": successes,
        "event_recall": successes / total,
        "event_recall_wilson95": wilson_interval(successes, total),
        "mean_horizon_penalized_delay_ticks": statistics.mean(
            r["mean_horizon_penalized_delay_ticks"] for r in rows
        ),
        "mutation_tick_alert_coverage": statistics.mean(
            r["mutation_tick_alert_coverage"] for r in rows
        ),
        "false_alarm_count": false_alarms,
        "clean_tick_count": clean_ticks,
        "false_alarms_per_1000_clean_ticks": 1000 * false_alarms / max(1, clean_ticks),
        "legitimate_transition_alert_count": transition_alerts,
        "legitimate_transition_tick_count": transition_ticks,
        "legitimate_transition_alert_wilson95": wilson_interval(transition_alerts, transition_ticks),
        "common_source_alert_count": sum(r["common_source_alert_count"] for r in rows),
        "policy_sha256": next(iter(policies)),
        "public_key_sha256": next(iter(keys)),
        "external_service_revision": next(iter(revisions)),
        "by_kind": stratified(rows, "kind"),
        "by_duration_bin": stratified(rows, "duration_bin"),
        "by_density_bin": stratified(rows, "density_bin"),
    }

def markdown(s: dict) -> str:
    ci = s["event_recall_wilson95"]
    tci = s["legitimate_transition_alert_wilson95"]
    lines = [
        "# Stage 33 — final independent external-verifier iteration",
        "",
        f"Fresh Open5GS runners: **{s['independent_live_runners']}**; attack episodes: **{s['total_attack_episodes']}**.",
        f"External verifier recall: **{s['event_recall']:.3f} ({s['event_detected']}/{s['total_attack_episodes']})**, Wilson 95% [{ci[0]:.3f}, {ci[1]:.3f}].",
        f"Mean horizon-penalized delay: **{s['mean_horizon_penalized_delay_ticks']:.2f} ticks**; mutation-tick coverage: **{s['mutation_tick_alert_coverage']:.3f}**.",
        f"Clean false alarms: **{s['false_alarm_count']}/{s['clean_tick_count']}**, {s['false_alarms_per_1000_clean_ticks']:.3f}/1000.",
        f"Legitimate-transition alerts: **{s['legitimate_transition_alert_count']}/{s['legitimate_transition_tick_count']}**, Wilson 95% [{tci[0]:.3f}, {tci[1]:.3f}].",
        f"Common-source negative-control alerts: **{s['common_source_alert_count']}**.",
        "",
        "Approved policy SHA-256: " + s["policy_sha256"],
        "External verifier public-key SHA-256: " + s["public_key_sha256"],
        "Pinned external service revision: " + s["external_service_revision"],
        "",
        "## Stratification",
        "",
        "| Stratum | Detected / total | Recall | Wilson 95% |",
        "|---|---:|---:|---:|",
    ]
    for title, group in (
        ("attack family", s["by_kind"]),
        ("duration", s["by_duration_bin"]),
        ("density", s["by_density_bin"]),
    ):
        lines.append(f"| **{title}** |  |  |  |")
        for name, row in group.items():
            w = row["wilson95"]
            lines.append(
                f"| {name} | {row['detected']}/{row['total']} | "
                f"{row['recall']:.3f} | [{w[0]:.3f}, {w[1]:.3f}] |"
            )
    lines.extend([
        "",
        "## Trust boundary",
        "",
        "The detector decision and verdict-signing key were executed in a Render service with auto-deploy disabled, outside the GitHub Actions runner/control-plane execution path.",
        "GitHub supplied label-free telemetry, then verified the externally signed verdict and joined private attack labels only in the final audit.",
        "This removes GitHub from the decision/key-custody path for the tested experiment, but telemetry capture still originates on GitHub-hosted runners; a malicious capture layer could fabricate observations before they reach the external verifier.",
        "",
    ])
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage33_report")
    args = parser.parse_args()
    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    verdicts = load_by_seed(root, "external_verdict.json")
    provenance = load_by_seed(root, "provenance.json")
    expected = set(EXPECTED_SEEDS)
    if any(set(group) != expected for group in (labels, verdicts, provenance)):
        raise AssertionError("Stage33 requires all eight fresh runners")
    rows = [score_seed(labels[s], verdicts[s], provenance[s]) for s in EXPECTED_SEEDS]
    summary = summarize(rows)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "seed_results.json").write_text(json.dumps(rows, indent=2), encoding="utf8")
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf8")
    report = markdown(summary)
    (output / "REPORT.md").write_text(report, encoding="utf8")
    print(report)

if __name__ == "__main__":
    main()
