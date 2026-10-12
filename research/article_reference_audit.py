"""Static audit of the frozen final-manuscript literature registry.

This is a reproducibility guard, not a live bibliographic database. It checks
corrections verified during the 2026-10-12 literature audit and prevents the
known stale metadata from reappearing silently.
"""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "article" / "references_verified.json"

EXPECTED_REL18 = {
    "3GPP-23501-R18": "18.12.0",
    "3GPP-29500-R18": "18.10.0",
    "3GPP-29501-R18": "18.7.0",
    "3GPP-29510-R18": "18.11.0",
    "3GPP-33501-R18": "18.12.0",
    "3GPP-33522-R18": "18.0.0",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    doc = json.loads(REGISTRY.read_text(encoding="utf8"))
    require(
        doc["freeze_date"] == "2026-10-12",
        "Literature freeze date changed unexpectedly",
    )

    refs = doc["references"]
    by_id = {ref["id"]: ref for ref in refs}
    require(
        len(by_id) == len(refs),
        "Duplicate reference IDs",
    )

    dois = [
        ref["doi"].lower()
        for ref in refs
        if ref.get("doi")
    ]
    require(
        len(dois) == len(set(dois)),
        "Duplicate DOI in verified registry",
    )

    for ref_id, version in EXPECTED_REL18.items():
        ref = by_id[ref_id]
        require(ref["release"] == "18", f"{ref_id}: release drift")
        require(
            ref["version"] == version,
            f"{ref_id}: expected {version}, got {ref['version']}",
        )

    scp_services = by_id["3GPP-29570-R19"]
    require(
        scp_services["release"] == "19"
        and scp_services["version"] == "19.3.0"
        and scp_services["status"] == "newer-context-only",
        "TS 29.570 must remain contextual, not a tested compatibility claim",
    )

    nist = by_id["NIST-CSWP36E"]
    require(
        "Sanjeev Sharma" in nist["authors"],
        "NIST CSWP 36E must cite Sanjeev Sharma",
    )
    require(
        nist["doi"] == "10.6028/NIST.CSWP.36E",
        "NIST DOI drift",
    )

    hoq = by_id["HOQ-2023"]
    require(
        hoq["year"] == 2024
        and hoq["conference_year"] == 2023
        and hoq["pages"] == "123-144",
        "Hoq/ESORICS publisher-year or pages reverted",
    )

    rad = by_id["LI-5GRAD-2023"]
    require(
        rad["pages"] == "1-2"
        and rad["doi"]
        == "10.1109/INFOCOMWKSHPS57453.2023.10226155",
        "5G-RAD metadata drift",
    )

    fivegac = by_id["THORN-5GAC-2024"]
    require(
        fivegac["pages"] == "66-77",
        "5GAC page range missing",
    )

    fivegcid = by_id["HU-5GCID-2025"]
    require(
        fivegcid["year"] == 2025,
        "5GCID year must be 2025, not 2026",
    )
    require(
        fivegcid["doi"] == "10.1016/j.comcom.2025.108375",
        "5GCID DOI drift",
    )

    sage = by_id["MANCA-SAGE5GC-2026"]
    require(
        "CEUR Workshop Proceedings 4198" in sage["venue"]
        and sage["status"] == "peer-reviewed-conference",
        "SAGE-5GC should use the ITASEC/SERICS 2026 CEUR record",
    )

    manias = by_id["MANIAS-DRIFT-2022"]
    require(
        manias["doi"]
        == "10.1109/MeditCom55741.2022.9928667"
        and manias["pages"] == "197-202",
        "Manias drift paper must use peer-reviewed MeditCom record",
    )

    vovk = by_id["VOVK-2021"]
    require(
        "PMLR 152" in vovk["venue"]
        and vovk["pages"] == "191-210",
        "Vovk citation should use PMLR publication",
    )

    edet = by_id["SHIN-EDETECTORS-2024"]
    require(
        edet["year"] == 2024
        and edet["pages"] == "229-260"
        and edet["doi"] == "10.51387/23-NEJSDS51",
        "E-detectors must use journal publication metadata",
    )

    for ref_id in (
        "BHATTACHARYYA-RAMDAS-2026",
        "LEVI-DUBIN-2026",
    ):
        require(
            by_id[ref_id]["status"] == "preprint",
            f"{ref_id} must remain explicitly labeled preprint",
        )

    patent = by_id["ORACLE-SCP-INTEGRITY-2025"]
    require(
        patent["priority_date"] == "2024-05-28"
        and patent["publication_date"] == "2025-12-04"
        and patent["assignee"] == "Oracle International Corp",
        "Oracle SCP-integrity prior-art metadata drift",
    )

    for required in (
        "CHO-5G-KPI-2025",
        "ELIADES-2026",
        "SHAER-2026",
        "GONG-SURVEY-2025",
        "CURRENT-WORK",
    ):
        require(
            required in by_id,
            f"Fresh 2025-2026 audit entry missing: {required}",
        )

    output = {
        "status": "PASS",
        "freeze_date": doc["freeze_date"],
        "reference_count": len(refs),
        "doi_count": len(dois),
        "release18_versions": EXPECTED_REL18,
        "critical_corrections": {
            "NIST_author": "Sanjeev Sharma",
            "5GCID_year": 2025,
            "Hoq_publisher_year": 2024,
            "Manias_peer_reviewed_DOI":
                "10.1109/MeditCom55741.2022.9928667",
            "e_detectors_journal_DOI":
                "10.51387/23-NEJSDS51",
            "Oracle_priority": "2024-05-28",
        },
        "note": (
            "Static frozen-registry audit. A new literature search is required "
            "if the manuscript is submitted substantially after 2026-10-12."
        ),
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
