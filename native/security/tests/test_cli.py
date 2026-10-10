from __future__ import annotations

import unittest
from pathlib import Path

from native.security.cli import Audit, status_for
from native.security.model import common_instances, load_config, main_instances


PROJECT_ROOT = Path(__file__).resolve().parents[3]


class AuditSelectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(PROJECT_ROOT / "native/security/configs/1gib.json")

    def test_unbounded_main_is_opt_in_but_bfv_remains(self) -> None:
        audit = Audit(self.config, None, "full", False, False)  # type: ignore[arg-type]
        selected_main = audit.selected_instances(main_instances(self.config, "dense", 1408))
        self.assertFalse(any(item.sensitivity for item in selected_main))
        self.assertEqual(len(audit.selected_instances(common_instances(self.config))), 1)

    def test_sensitivity_flag_keeps_unbounded_main(self) -> None:
        audit = Audit(self.config, None, "full", False, True)  # type: ignore[arg-type]
        selected_main = audit.selected_instances(main_instances(self.config, "dense", 1408))
        self.assertTrue(any(item.sensitivity for item in selected_main))

    @staticmethod
    def component(status: str, bits: float | None, complete: bool) -> dict:
        role = {"status": status, "minimum_bits": bits, "complete": complete}
        return {"paper": dict(role), "modern": dict(role), "conditional": False}

    def test_partial_suite_can_prove_failure_but_not_pass(self) -> None:
        passing = self.component("pass", 140.0, True)
        partial_failure = self.component("fail", 120.0, False)
        partial_pass = self.component("pass", 140.0, False)
        correctness = {"status": "pass"}
        self.assertEqual(
            status_for("full", correctness, passing, passing, partial_failure), "FAIL"
        )
        self.assertEqual(
            status_for("full", correctness, passing, passing, partial_pass), "INCONCLUSIVE"
        )


if __name__ == "__main__":
    unittest.main()
