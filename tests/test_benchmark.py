from __future__ import annotations

import json
import unittest
from pathlib import Path

from small_client_vpir.benchmark import BENCHMARK_SCHEMA, _residue_bytes, run_benchmark


class BenchmarkSchemaTests(unittest.TestCase):
    def test_small_client_reports_all_four_phases_and_state_classes(self) -> None:
        result = run_benchmark(protocol="small-client", rows=4, columns=8, queries=2)
        self.assertEqual(result["schema"], BENCHMARK_SCHEMA)
        self.assertTrue(result["all_results_correct_and_accepted"])
        timings = result["timings_seconds"]
        for field in (
            "global_setup",
            "database_preprocessing",
            "client_registration_begin_client",
            "client_registration_server",
            "client_registration_finalize_client",
            "query_preprocessing_begin_client_total",
            "query_preprocessing_server_total",
            "query_preprocessing_finalize_client_total",
            "online_build_client_total",
            "online_server_total",
            "online_verify_client_total",
        ):
            self.assertIn(field, timings)
        sizes = result["logical_bytes"]
        for field in (
            "public_matrix_expanded",
            "server_database_and_hint",
            "client_persistent_compressed",
            "client_registration_upload_ciphertext_and_evk",
            "client_registration_download_ciphertext",
            "client_registration_ephemeral_peak_estimate",
            "query_token_before_consumption",
            "query_ephemeral_peak_estimate",
        ):
            self.assertGreater(sizes[field], 0)

    def test_via_placeholder_never_fabricates_results(self) -> None:
        small_client = run_benchmark(
            protocol="small-client", rows=4, columns=8, queries=2
        )
        result = run_benchmark(protocol="via", rows=4, columns=8, queries=2)
        self.assertEqual(set(result), set(small_client))
        self.assertEqual(result["status"], "not-integrated")
        self.assertIsNone(result["timings_seconds"])
        self.assertIsNone(result["logical_bytes"])
        self.assertIsNone(result["all_results_correct_and_accepted"])

        profile_path = (
            Path(__file__).resolve().parents[1]
            / "comparators"
            / "via"
            / "profile.json"
        )
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        self.assertEqual(profile["implementation_status"], result["status"])
        self.assertEqual(profile["runtime_benchmark_schema"], result["schema"])

    def test_power_of_two_plaintext_modulus_uses_canonical_width(self) -> None:
        self.assertEqual(_residue_bytes(256), 1)
        self.assertEqual(_residue_bytes(257), 2)


if __name__ == "__main__":
    unittest.main()
