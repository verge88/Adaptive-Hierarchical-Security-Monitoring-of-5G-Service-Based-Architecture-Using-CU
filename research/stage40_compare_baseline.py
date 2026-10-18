"""Stage 40 preregistered contrast: lifecycle-aware signed full policy vs witness join.

Uses repository's actual full-policy baseline and StreamRelationalVerifier; no
label enters either decision function. Read the labels only after decisions.
"""
import argparse
import copy
import hmac
import json
import time
from collections import defaultdict
from pathlib import Path

from stage39_kie import FullProfilePolicy, StreamRelationalVerifier, hmac_hex
from stage39_orchestration_eval import (
    LifecycleAuthority, LifecycleAuthorizationError, signed_full_policy_alert,
)


def check_witness(envelope, witness_key, case_id, policy_digest):
    doc = envelope["payload"]
    if not hmac.compare_digest(
        str(envelope.get("hmac_sha256", "")), hmac_hex(witness_key, doc)
    ):
        raise RuntimeError("invalid witness HMAC")
    if doc["case_id"] != case_id or doc["policy_sha256"] != policy_digest:
        raise RuntimeError("witness context mismatch")
    if abs(int(time.time() * 1000) - int(doc["issued_at_ms"])) > 60000:
        raise RuntimeError("witness expired")
    return doc["witnesses"]


def confusion():
    return {"TP": 0, "FN": 0, "FP": 0, "TN": 0}


def update(m, attacked, alert):
    name = "TP" if attacked and alert else "FN" if attacked else "FP" if alert else "TN"
    m[name] += 1


def score(decisions, labels):
    lab = {row["case_id"]: row for row in labels}
    if len(lab) != len(labels) or set(lab) != {r["case_id"] for r in decisions}:
        raise RuntimeError("labels do not match exactly the verified decision set")
    methods = ("lifecycle_full_policy", "relational_policy_plus_witness")
    scores = {name: confusion() for name in methods}
    per_family = defaultdict(lambda: {name: confusion() for name in methods})
    for row in decisions:
        label = lab[row["case_id"]]
        attacked = bool(label["attacked"])
        for method in methods:
            alert = bool(row["alerts"][method])
            update(scores[method], attacked, alert)
            update(per_family[label["family"]][method], attacked, alert)
    for method in methods:
        mat = scores[method]
        mat["recall"] = mat["TP"] / (mat["TP"] + mat["FN"])
        mat["false_positive_rate"] = mat["FP"] / (mat["FP"] + mat["TN"])
    return scores, dict(per_family)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--cases", type=Path, required=True)
    ap.add_argument("--labels", type=Path, required=True)
    ap.add_argument("--event-key-file", type=Path, required=True)
    ap.add_argument("--witness-key-file", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    policy = FullProfilePolicy.load(args.policy)
    cases = json.loads(args.cases.read_text(encoding="utf-8"))
    event_key = bytes.fromhex(args.event_key_file.read_text().strip())
    witness_key = bytes.fromhex(args.witness_key_file.read_text().strip())
    if event_key == witness_key:
        raise RuntimeError("event and witness authorities must have different keys")

    auth = LifecycleAuthority(event_key, policy.digest)
    decisions = []
    signed_events = 0
    first_event = None
    last_event = None
    for case in cases:
        event = case["lifecycle"]
        slot = None
        operation = None
        if event is not None:
            verified = auth.verify(event)
            signed_events += 1
            operation = verified["operation"]
            slot = verified["slot"]
            first_event = first_event or event
            last_event = event

        verified_witnesses = check_witness(
            case["signed_witness"], witness_key, case["case_id"], policy.digest
        )
        observed = case["observed_profiles"]
        baseline = signed_full_policy_alert(
            policy, case["pre_profiles"], observed, operation, slot, None
        )
        proposal = StreamRelationalVerifier(policy)
        if event is not None:
            proposal.begin_transition(operation, slot)
        relational = proposal.verify(observed, verified_witnesses)
        decisions.append({
            "case_id": case["case_id"],
            "alerts": {
                "lifecycle_full_policy": bool(baseline),
                "relational_policy_plus_witness": bool(relational),
            },
            "reasons": {
                "lifecycle_full_policy": baseline,
                "relational_policy_plus_witness": relational,
            },
        })

    if not first_event or not last_event:
        raise RuntimeError("missing signed lifecycle events")
    # Transport / signature integrity controls; distinct from attack-detection scores.
    replay_rejected = tamper_rejected = witness_tamper_rejected = False
    try:
        auth.verify(last_event)
    except LifecycleAuthorizationError:
        replay_rejected = True
    tampered = copy.deepcopy(first_event)
    tampered["payload"]["slot"] = "invalid-slot"
    try:
        LifecycleAuthority(event_key, policy.digest).verify(tampered)
    except LifecycleAuthorizationError:
        tamper_rejected = True
    changed_witness = copy.deepcopy(cases[0]["signed_witness"])
    changed_witness["payload"]["witnesses"] = {}
    try:
        check_witness(changed_witness, witness_key, cases[0]["case_id"], policy.digest)
    except RuntimeError:
        witness_tamper_rejected = True
    if not (replay_rejected and tamper_rejected and witness_tamper_rejected):
        raise RuntimeError("authenticity controls failed")

    # The evaluation deliberately joins private labels only after all decisions.
    labels = json.loads(args.labels.read_text(encoding="utf-8"))
    scores, per_family = score(decisions, labels)
    baseline, proposal = scores["lifecycle_full_policy"], scores["relational_policy_plus_witness"]
    report = {
        "experiment": "stage40 strong signed full-profile lifecycle baseline versus independent witness",
        "kind": "software fixture; NOT a new live Open5GS trial",
        "policy_sha256": policy.digest,
        "total_cases": len(decisions),
        "unique_slots": len(policy.slots),
        "distinct_case_families": len(set(row["family"] for row in labels)),
        "signed_lifecycle_events_verified": signed_events,
        "signed_witness_envelopes_verified": len(decisions),
        "tampered_event_rejected": tamper_rejected,
        "replayed_event_rejected": replay_rejected,
        "tampered_witness_rejected": witness_tamper_rejected,
        "labels_accessed_after_prediction": True,
        "confusion": scores,
        "per_family": per_family,
        "discordant_pairs_proposal_only_detected": sum(
            row["alerts"]["relational_policy_plus_witness"] and
            not row["alerts"]["lifecycle_full_policy"] for row in decisions
        ),
        "assumptions": [
            "The adversary controls NRF-facing profile bytes, not the policy, event key or witness key.",
            "Both methods receive the same signed policy and authenticated lifecycle events.",
            "The competitor is the strong existing full-policy lifecycle comparator, not a snapshot.",
            "Only the proposal verifies independently MAC-bound live-instance witnesses.",
            "Equal-information full-policy + witness comparators can match the proposal.",
            "Cases are constructed, not independent random attacks or actual process restarts.",
            "Witness HMAC authenticates a synthetic witness claim, not runtime code attestation.",
        ],
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "stage40_decisions.json").write_text(
        json.dumps(decisions, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.output / "stage40_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# Stage40: independent witness vs signed full lifecycle policy",
        "",
        "Synthetic signed cases; no live NF process attacks. Same policy and signed events.",
        "Only the relational method uses the independently authenticated witness.",
        "",
        "| Detector | TP | FN | FP | TN | Recall | FPR |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for method, m in scores.items():
        lines.append(
            f"| {method} | {m['TP']} | {m['FN']} | {m['FP']} | {m['TN']} | "
            f"{m['recall']:.3f} | {m['false_positive_rate']:.3f} |"
        )
    lines += [
        "",
        "Per-family counts and the signed-event integrity tests are in stage40_report.json.",
        "The difference is attributable to the extra independent witness information,",
        "not an algorithmic advantage at identical information or proof for live operators.",
    ]
    (args.output / "STAGE40_RESULT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if proposal["FN"] or proposal["FP"] or baseline["FP"]:
        raise RuntimeError("false positive or proposed-detector miss in predeclared cases")
    if baseline["FN"] == 0:
        raise RuntimeError("preregistered identity-spoof counterexample was not observed")


if __name__ == "__main__":
    main()
