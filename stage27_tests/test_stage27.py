"""Stage27 software-attested common-source failure invariants."""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from research.stage27_attestation_authority import create_bundle
from research.stage27_capture import (
    compromised_witness_object,
    ordinal_projection,
)
from research.stage27_live_detect import (
    detect,
    verify_attestation_bundle,
)


def true_witness() -> dict:
    return {
        "nfInstances": [
            {
                "nfInstanceId": "11111111-1111-4111-8111-111111111111",
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
            },
            {
                "nfInstanceId": "22222222-2222-4222-8222-222222222222",
                "nfType": "NSSF",
                "nfStatus": "REGISTERED",
            },
        ]
    }


def phantom_consumer() -> dict:
    obj = json.loads(json.dumps(true_witness()))
    obj["nfInstances"].append(
        {
            "nfInstanceId": "26000000-0000-4000-8000-000000000026",
            "nfType": "NSSF",
            "nfStatus": "REGISTERED",
        }
    )
    return obj


class Stage27Tests(unittest.TestCase):
    def test_authority_exports_public_bundle_without_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bundle"
            provenance = create_bundle(Path("."), root)
            self.assertTrue((root / "manifest.json").exists())
            self.assertTrue((root / "public_key.pem").exists())
            self.assertTrue((root / "signature.bin").exists())
            self.assertFalse((root / "private.pem").exists())
            self.assertFalse(provenance["private_key_exported"])
            verified = verify_attestation_bundle(root)
            self.assertEqual(
                verified["manifest"]["deployment_contract"][
                    "expected_nssf_count"
                ],
                2,
            )

    def test_manifest_tamper_breaks_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bundle"
            create_bundle(Path("."), root)
            manifest = json.loads(
                (root / "manifest.json").read_text(encoding="utf8")
            )
            manifest["expected_profiles"].append(
                {
                    "slot": "nssf-3",
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                }
            )
            (root / "manifest.json").write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")),
                encoding="utf8",
            )
            with self.assertRaises(ValueError):
                verify_attestation_bundle(root)

    def test_compromised_witness_generates_same_false_state_independently(self):
        false_witness = compromised_witness_object(true_witness(), 30)
        self.assertEqual(
            ordinal_projection(false_witness),
            ordinal_projection(phantom_consumer()),
        )
        self.assertEqual(
            len(ordinal_projection(false_witness)["nfInstances"]),
            3,
        )

    def test_signed_third_domain_restores_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            create_bundle(Path("."), bundle)

            rows = []
            for tick in range(46):
                projection = (
                    ordinal_projection(phantom_consumer())
                    if 30 <= tick < 42
                    else ordinal_projection(true_witness())
                )
                rows.append(
                    {
                        "seed": 99401,
                        "tick": tick,
                        "consumer_projection": projection,
                        "compromised_witness_projection": json.loads(
                            json.dumps(projection)
                        ),
                        "pairwise_false_state_exact": True,
                    }
                )

            result = detect(rows, bundle)
            attested = result["attested_reference"]["ticks"]
            compromised = result["compromised_pair"]["ticks"]
            self.assertTrue(
                any(
                    row["stage21_combined_alert"]
                    for row in attested[30:42]
                )
            )
            self.assertFalse(
                any(row["stage21_combined_alert"] for row in compromised)
            )
            self.assertTrue(
                result["protocol"]["attestation_signature_verified"]
            )

    def test_blind_detector_imports_no_capture_labels(self):
        import research.stage27_live_detect as module

        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage27_capture" not in name for name in imported)
        )
        self.assertNotIn("labels_from_native_nrf_log", module.__dict__)


if __name__ == "__main__":
    unittest.main()
