from __future__ import annotations

import copy
import unittest

from native.experiments.paper_config import (
    DEFAULT_CHECKSUM,
    DEFAULT_MANIFEST,
    ManifestError,
    load_manifest,
    normalize_profile,
    profile_values,
    validate_manifest,
)
from native.experiments.run_matrix import balanced_rows, build_schedule, deterministic_query


class PaperConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_manifest(DEFAULT_MANIFEST, DEFAULT_CHECKSUM)

    def test_frozen_near_square_layouts(self) -> None:
        expected = {
            "256mib": (16384, 16384, 256 << 20, 8, 4),
            "512mib": (32768, 16384, 512 << 20, 8, 8),
            "1gib": (32768, 32768, 1 << 30, 16, 8),
            "2gib": (65536, 32768, 2 << 30, 16, 16),
            "4gib": (65536, 65536, 4 << 30, 32, 16),
        }
        for name, values in expected.items():
            with self.subTest(name=name):
                size = self.manifest["sizes"][name]
                self.assertEqual(
                    (
                        size["rows"],
                        size["columns"],
                        size["logical_bytes"],
                        size["main_pad_blocks"],
                        size["offline_pad_blocks"],
                    ),
                    values,
                )

    def test_legacy_aliases_normalize(self) -> None:
        self.assertEqual(normalize_profile(self.manifest, "baseline"), "dense")
        self.assertEqual(
            normalize_profile(self.manifest, "hybrid"), "negacyclic-both"
        )
        values = profile_values(self.manifest, "4gib", "hybrid")
        self.assertEqual(values["main_pad_blocks"], "32")
        self.assertEqual(values["offline_pad_blocks"], "16")
        self.assertEqual(values["sis_infinity_bound"], "33488896")

    def test_crypto_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["cryptographic_parameters"]["main_ring_degree"] = 1024
        with self.assertRaises(ManifestError):
            validate_manifest(changed)

    def test_balanced_order_and_query_alignment(self) -> None:
        profiles = list(self.manifest["profiles"])
        rows = balanced_rows(profiles)
        self.assertEqual(len(rows), len(profiles))
        self.assertTrue(all(set(row) == set(profiles) for row in rows))
        for size_name in ("256mib", "512mib", "1gib", "2gib", "4gib"):
            size = self.manifest["sizes"][size_name]
            index = deterministic_query(size, 20260905, size_name, 0)
            self.assertLess(index, size["rows"] * size["columns"])
            self.assertEqual((index // size["columns"]) % size["stack_cells"], 0)

    def test_schedule_freezes_manifest_digest(self) -> None:
        digest = "a" * 64
        schedule = build_schedule(
            self.manifest,
            ["1gib"],
            ["dense"],
            1,
            20260905,
            "test-session",
            digest,
        )
        self.assertEqual(schedule["manifest_sha256"], digest)


if __name__ == "__main__":
    unittest.main()
