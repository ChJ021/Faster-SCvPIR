from __future__ import annotations

import json
import unittest
from pathlib import Path

from small_client_vpir.parameters import ProtocolParameters, reference_parameters
from small_client_vpir.algebra import centered_matrix, decode_plaintext, encode_plaintext, infinity_norm
from small_client_vpir.protocol import setup


ROOT = Path(__file__).resolve().parents[1]


class ParameterTests(unittest.TestCase):
    def test_general_sis_bound_is_selected(self) -> None:
        profile = reference_parameters()
        self.assertEqual(
            profile.general_sis_beta,
            (2 * profile.ell + 1) * profile.proof_norm_bound,
        )
        self.assertNotEqual(
            profile.general_sis_beta,
            profile.honest_hint_beta_for_comparison,
        )

    def test_reference_profile_is_fail_closed_for_production(self) -> None:
        profile = reference_parameters()
        audit = profile.audit()
        self.assertFalse(audit.production_ready)
        self.assertIn("reference-only profiles", " ".join(audit.blockers))
        with self.assertRaises(ValueError):
            profile.require_production_ready()

    def test_production_template_is_intentionally_unapproved(self) -> None:
        profile = ProtocolParameters.load(ROOT / "configs" / "production-template.json")
        audit = profile.audit()
        self.assertFalse(audit.production_ready)
        self.assertGreater(profile.general_sis_beta, profile.honest_hint_beta_for_comparison)
        self.assertTrue(any("SIS" in blocker or "estimator" in blocker for blocker in audit.blockers))
        with self.assertRaises(ValueError):
            setup(profile)

    def test_production_ledger_rejects_split_variant(self) -> None:
        value = ProtocolParameters.load(
            ROOT / "configs" / "production-template.json"
        ).to_dict()
        value["protocol_variant"] = "experimental-split-qlp-reference"
        profile = ProtocolParameters.from_dict(value)
        failed = {check.name for check in profile.audit().checks if not check.passed}
        self.assertIn("production-protocol-variant", failed)

    def test_security_budget_counts_lifetime_registrations(self) -> None:
        one = reference_parameters().audit()
        value = reference_parameters().to_dict()
        value["max_registrations_per_client_lifetime"] = 2
        two = ProtocolParameters.from_dict(value).audit()
        self.assertEqual(
            two.cumulative_correctness_failure_bound,
            2 * one.cumulative_correctness_failure_bound,
        )
        self.assertEqual(
            two.cumulative_statistical_failure_bound,
            2 * one.cumulative_statistical_failure_bound,
        )

    def test_computational_lifetime_ledger_adds_multi_target_margins(self) -> None:
        value = ProtocolParameters.load(
            ROOT / "configs" / "production-template.json"
        ).to_dict()
        value["max_registrations_per_client_lifetime"] = 3
        value["max_queries_per_registration"] = 5
        value["security_evidence"].update(
            {
                "lifetime_target_bits": 128,
                "query_lwe_single_instance_bits": 132,
                "registration_lhe_single_instance_bits": 130,
                "hint_fhe_rlwe_single_instance_bits": 132,
                "sis_general_bound_single_instance_bits": 132,
            }
        )
        audit = ProtocolParameters.from_dict(value).audit()
        ledger = {
            entry.primitive: entry for entry in audit.computational_security_ledger
        }

        for primitive in ("query_lwe", "hint_fhe_rlwe", "sis_general_bound"):
            self.assertEqual(ledger[primitive].lifetime_target_count, 15)
            self.assertEqual(ledger[primitive].multi_target_margin_bits, 4)
            self.assertEqual(
                ledger[primitive].required_single_instance_bits_for_lifetime,
                132,
            )
        self.assertEqual(ledger["registration_lhe"].lifetime_target_count, 3)
        self.assertEqual(ledger["registration_lhe"].multi_target_margin_bits, 2)
        self.assertEqual(
            ledger["registration_lhe"].required_single_instance_bits_for_lifetime,
            130,
        )

        checks = {check.name: check.passed for check in audit.checks}
        self.assertTrue(checks["query-lwe-single-instance-estimate"])
        self.assertTrue(checks["registration-lhe-single-instance-estimate"])
        self.assertTrue(checks["hint-fhe-rlwe-single-instance-estimate"])
        self.assertTrue(checks["sis-general-single-instance-estimate"])

        value["security_evidence"]["query_lwe_single_instance_bits"] = 131
        failed = {
            check.name
            for check in ProtocolParameters.from_dict(value).audit().checks
            if not check.passed
        }
        self.assertIn("query-lwe-single-instance-estimate", failed)

    def test_self_reported_fake_evidence_cannot_clear_native_hard_blocker(self) -> None:
        value = ProtocolParameters.load(ROOT / "configs" / "production-template.json").to_dict()
        value["query_secret_distribution"] = "uniform-ternary"
        value["query_error_distribution"] = "centered-binomial-variance-8"
        value["registration_lhe"].update(
            {
                "status": "selected",
                "dimension": 4096,
                "plaintext_modulus": 8388608,
                "ciphertext_moduli_bits": [60, 60],
                "secret_distribution": "fake",
                "error_distribution": "fake",
                "error_parameter": 1.0,
            }
        )
        value["hint_fhe"].update(
            {
                "status": "selected",
                "dimension": 8192,
                "plaintext_modulus": value["ciphertext_modulus"],
                "ciphertext_moduli_bits": [62, 62],
                "secret_distribution": "fake",
                "error_distribution": "fake",
                "error_parameter": 1.0,
            }
        )
        value["security_evidence"].update(
            {
                "query_lwe_single_instance_bits": 999,
                "registration_lhe_single_instance_bits": 999,
                "hint_fhe_rlwe_single_instance_bits": 999,
                "sis_general_bound_single_instance_bits": 999,
                "estimator_commit": "not-real",
                "artifact_sha256": "0" * 64,
                "public_matrix_seed_source": "fake-source",
                "setup_transcript_sha256": "0" * 64,
            }
        )
        audit = ProtocolParameters.from_dict(value).audit()
        self.assertFalse(audit.production_ready)
        self.assertIn(
            "audited-native-backend-integrated",
            {check.name for check in audit.checks if not check.passed},
        )

    def test_round_trip_profile_json(self) -> None:
        profile = reference_parameters()
        recovered = ProtocolParameters.from_dict(json.loads(profile.canonical_bytes()))
        self.assertEqual(profile, recovered)

    def test_checked_in_dev_profile_matches_factory(self) -> None:
        self.assertEqual(
            ProtocolParameters.load(ROOT / "configs" / "dev-toy.json"),
            reference_parameters(),
        )

    def test_boolean_integer_is_rejected(self) -> None:
        value = reference_parameters().to_dict()
        value["database_rows"] = True
        with self.assertRaises(ValueError):
            ProtocolParameters.from_dict(value)

    def test_malformed_security_evidence_is_rejected(self) -> None:
        value = reference_parameters().to_dict()
        value["security_evidence"] = {
            "query_lwe_single_instance_bits": "128"
        }
        profile = ProtocolParameters.from_dict(value)
        self.assertFalse(profile.audit().production_ready)
        value["security_evidence"] = {"query_lwe_bits": 128}
        with self.assertRaisesRegex(ValueError, "unexpected fields"):
            ProtocolParameters.from_dict(value)
        value["security_evidence"] = "not-an-object"
        with self.assertRaises(ValueError):
            ProtocolParameters.from_dict(value)

    def test_q_must_exceed_general_sis_bound(self) -> None:
        value = reference_parameters(rows=32, columns=8).to_dict()
        value["ciphertext_modulus"] = 65537
        value["database_rows"] = 256
        value["proof_norm_bound"] = 4096
        profile = ProtocolParameters.from_dict(value)
        failed = {check.name for check in profile.audit().checks if not check.passed}
        self.assertIn("nontrivial-general-sis-bound", failed)
        with self.assertRaises(ValueError):
            setup(profile)

    def test_composite_q_is_rejected_by_executable_gate(self) -> None:
        value = reference_parameters().to_dict()
        value["ciphertext_modulus"] = 65535
        value["hint_fhe"]["plaintext_modulus"] = 65535
        profile = ProtocolParameters.from_dict(value)
        failed = {check.name for check in profile.audit().checks if not check.passed}
        self.assertIn("q-is-prime", failed)
        with self.assertRaises(ValueError):
            setup(profile)

    def test_correctness_and_statistical_budgets_fail_closed(self) -> None:
        correctness = reference_parameters().to_dict()
        correctness["correctness_delta"] = 0.1
        correctness_profile = ProtocolParameters.from_dict(correctness)
        failed = {
            check.name for check in correctness_profile.audit().checks if not check.passed
        }
        self.assertIn("cumulative-correctness-budget", failed)

        statistical = reference_parameters().to_dict()
        statistical["statistical_failure_budget_bits"] = 128
        statistical_profile = ProtocolParameters.from_dict(statistical)
        failed = {
            check.name for check in statistical_profile.audit().checks if not check.passed
        }
        self.assertIn("provisional-cumulative-statistical-budget", failed)

    def test_reference_execution_binds_sampler_names(self) -> None:
        value = reference_parameters().to_dict()
        value["query_error_distribution"] = "different-sampler"
        with self.assertRaisesRegex(ValueError, "reference sampler"):
            setup(ProtocolParameters.from_dict(value))

        value = reference_parameters().to_dict()
        value["error_sigma"] = 0.5
        with self.assertRaisesRegex(ValueError, "Hoeffding"):
            setup(ProtocolParameters.from_dict(value))

    def test_executable_gate_binds_hint_plaintext_modulus(self) -> None:
        value = reference_parameters().to_dict()
        value["hint_fhe"]["plaintext_modulus"] = 257
        profile = ProtocolParameters.from_dict(value)
        with self.assertRaisesRegex(ValueError, "plaintext modulus must equal q"):
            setup(profile)

    def test_regev_encoding_uses_floor_q_over_p(self) -> None:
        self.assertEqual(encode_plaintext(3, 16, 65537), (65537 // 16) * 3)
        for value in range(16):
            self.assertEqual(decode_plaintext(encode_plaintext(value, 16, 65537), 16, 65537), value)

    def test_centered_residue_norm_semantics(self) -> None:
        self.assertEqual(infinity_norm(centered_matrix(((65536, 1),), 65537)), 1)
        with self.assertRaises(ValueError):
            centered_matrix(((65537,),), 65537)


if __name__ == "__main__":
    unittest.main()
