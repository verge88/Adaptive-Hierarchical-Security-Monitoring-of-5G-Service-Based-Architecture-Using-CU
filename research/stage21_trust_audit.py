"""Static consistency audit for the Stage-21 trust model.

This audit does not prove runtime security. It prevents documentation drift by
checking that the machine-readable trust contract remains consistent with the
evaluated Stage-21 source architecture.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf8")


def imported_modules(source: str) -> list[str]:
    tree = ast.parse(source)
    modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
    return modules


def require(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)


def main():
    model = json.loads(
        read("stage21/trust_model.json")
    )
    gateway = read("research/stage21_gateway.py")
    capture = read("research/stage21_capture.py")
    detector = read("research/stage21_live_detect.py")

    checks = {}

    checks["manifest_not_truth_oracle"] = bool(
        model["not_a_truth_oracle"]
    )
    require(
        checks["manifest_not_truth_oracle"],
        "Trust model must state that reconciliation is not a truth oracle",
    )

    checks["current_lab_native_scp_trusted"] = any(
        entity["id"] == "native_scp"
        and entity["current_lab_trust"] == "trusted"
        and not entity["attacker_control_current_lab"]
        for entity in model["entities"]
    )
    require(
        checks["current_lab_native_scp_trusted"],
        "Native SCP trust assumption missing",
    )

    checks["current_lab_native_nrf_trusted"] = any(
        entity["id"] == "native_nrf"
        and entity["current_lab_trust"] == "trusted"
        and not entity["attacker_control_current_lab"]
        for entity in model["entities"]
    )
    require(
        checks["current_lab_native_nrf_trusted"],
        "Native NRF trust assumption missing",
    )

    upstream_index = gateway.find(
        "upstream = await h2_exchange("
    )
    payload_index = gateway.find(
        "payload = json.loads(upstream.body)"
    )
    mutation_index = gateway.find(
        "payload, mutated, field = mutate_payload("
    )
    checks["gateway_mutation_after_native_upstream"] = (
        upstream_index >= 0
        and payload_index > upstream_index
        and mutation_index > payload_index
    )
    require(
        checks["gateway_mutation_after_native_upstream"],
        "Consumer mutation is no longer clearly after native upstream response",
    )

    checks["gateway_uses_native_scp_nrf"] = (
        "NATIVE_SCP" in gateway
        and "NRF_PATH" in gateway
        and 'target="http://nrf:80"' in gateway
    )
    require(
        checks["gateway_uses_native_scp_nrf"],
        "Gateway no longer clearly traverses native SCP->NRF",
    )

    checks["capture_has_independent_reference"] = (
        "async def trusted_reference()" in capture
        and "await h2_exchange(" in capture
        and "NATIVE_SCP" in capture
        and "NRF_PATH" in capture
    )
    require(
        checks["capture_has_independent_reference"],
        "Trusted nearby reference path missing from capture",
    )

    modules = imported_modules(detector)
    checks["detector_does_not_import_fault_gateway"] = all(
        "stage21_gateway" not in module
        for module in modules
    )
    require(
        checks["detector_does_not_import_fault_gateway"],
        "Blind detector imports private fault gateway",
    )

    checks["detector_does_not_read_private_labels"] = (
        "private_labels.json" not in detector
        and "ATTACK_KINDS" not in detector
        and "build_private_schedule" not in detector
    )
    require(
        checks["detector_does_not_read_private_labels"],
        "Blind detector source references private labels/schedule",
    )

    boundary = [
        item
        for item in model["tested_attack_classes"]
        if "cross-profile identity swap" in item["class"]
    ]
    checks["known_relational_boundary_preserved"] = (
        len(boundary) == 1
        and boundary[0]["current_live_evidence"]
        == "known blind spot"
        and float(boundary[0][
            "stage21_replication_recall"
        ]) == 0.0
    )
    require(
        checks["known_relational_boundary_preserved"],
        "Known relational semantic blind spot is not preserved",
    )

    forbidden = model["claim_boundary"][
        "forbidden_overclaim"
    ].lower()
    checks["forbidden_overclaim_names_common_components"] = (
        "scp" in forbidden
        and "nrf" in forbidden
        and (
            "byzantine" in forbidden
            or "multi-point" in forbidden
        )
    )
    require(
        checks[
            "forbidden_overclaim_names_common_components"
        ],
        "Claim boundary must forbid SCP/NRF/common Byzantine overclaim",
    )

    output = {
        "model_id": model["model_id"],
        "schema_version": model["schema_version"],
        "status": "PASS",
        "checks": checks,
        "note": (
            "Static architecture consistency audit only; "
            "not a cryptographic or runtime proof."
        ),
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
