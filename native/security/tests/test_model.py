from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from native.security.model import (
    ConfigError,
    candidate_values,
    common_instances,
    correctness_analysis,
    honest_h_sis_bound,
    load_config,
    logical_database_bytes,
    main_instances,
    offline_instances,
    profile_kinds,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
CONFIG_ROOT = PROJECT_ROOT / "native/security/configs"


class SecurityModelTest(unittest.TestCase):
    def load(self, name: str) -> dict:
        return load_config(CONFIG_ROOT / name)

    def test_shipped_database_sizes(self) -> None:
        expected = {
            "512mib.json": 512 << 20,
            "1gib.json": 1 << 30,
            "2gib.json": 2 << 30,
            "4gib.json": 4 << 30,
        }
        for name, size in expected.items():
            with self.subTest(name=name):
                config = self.load(name)
                self.assertEqual(logical_database_bytes(config), size)
                self.assertEqual(correctness_analysis(config)["status"], "pass")

    def test_exact_distributions_and_samples(self) -> None:
        config = self.load("2gib.json")
        main_instances_all = main_instances(config, "dense", 1408)
        offline_instances_all = offline_instances(config, "dense", 2816)
        main = main_instances_all[0]
        offline = offline_instances_all[0]
        self.assertEqual(main.error, {"kind": "centered_binomial", "eta": 16})
        self.assertEqual(main.secret, {"kind": "uniform", "a": -1, "b": 1})
        self.assertEqual(main.actual_samples, 32768)
        self.assertEqual(main_instances_all[1].m, "infinity")
        self.assertTrue(main_instances_all[1].sensitivity)
        self.assertEqual(offline.error, {"kind": "discrete_gaussian", "stddev": 6.4})
        self.assertEqual(offline.actual_samples, 65536)
        self.assertEqual(offline_instances_all[1].m, "infinity")
        self.assertTrue(offline_instances_all[1].sensitivity)

    def test_honest_h_bound(self) -> None:
        bound = honest_h_sis_bound(self.load("1gib.json"))
        self.assertEqual(bound["proof_bound_B"], 8388608)
        self.assertEqual(bound["database_infinity_bound"], 255)
        self.assertEqual(bound["sis_infinity_bound"], 16744448)
        large_bound = honest_h_sis_bound(self.load("4gib.json"))
        self.assertEqual(large_bound["proof_bound_B"], 16777216)
        self.assertEqual(large_bound["sis_infinity_bound"], 33488896)

    def test_profile_assumption_mapping(self) -> None:
        self.assertEqual(profile_kinds("baseline"), ("dense", "dense"))
        self.assertEqual(profile_kinds("ypir-main"), ("ring", "dense"))
        self.assertEqual(profile_kinds("distpir-offline"), ("dense", "ring"))
        self.assertEqual(profile_kinds("hybrid"), ("ring", "ring"))
        ring_main = main_instances(self.load("1gib.json"), "ring", 2048)
        self.assertTrue(any(item.primitive == "Ring/Module-SIS" and item.conditional for item in ring_main))
        ring_offline = offline_instances(self.load("1gib.json"), "ring", 4096)
        self.assertEqual({item.primitive for item in ring_offline}, {"RLWE"})

    def test_bfv_uses_product_modulus_and_unbounded_samples(self) -> None:
        config = self.load("1gib.json")
        instance = common_instances(config)[0]
        self.assertEqual(instance.q, 19988226643746817 * 19988226643402753)
        self.assertEqual(instance.m, "infinity")
        self.assertEqual(config["parameters"]["fhe"]["plaintext_modulus"], 4278255617)
        self.assertEqual(config["parameters"]["fhe"]["gadget_log_bases"], [13, 14])
        self.assertEqual(correctness_analysis(self.load("4gib.json"))["fhe_response_blocks"], 32)

    def test_candidate_expansion(self) -> None:
        config = self.load("1gib.json")
        values = candidate_values(config, "main", "dense")
        self.assertEqual(values[0], 1024)
        self.assertEqual(values[-1], 2048)
        self.assertEqual(values[1] - values[0], 64)
        self.assertEqual(candidate_values(config, "main", "ring", runtime_only=True), [2048])

    def test_invalid_ntt_degree_is_rejected(self) -> None:
        config = self.load("1gib.json")
        config["candidates"]["main_ring_degrees"] = [1536]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
