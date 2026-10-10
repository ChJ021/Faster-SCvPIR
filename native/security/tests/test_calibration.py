from __future__ import annotations

import unittest

from native.security.calibrate import REFERENCE_BITS, calibration_instances


class CalibrationDefinitionTest(unittest.TestCase):
    def test_ypir_paper_points_are_exact(self) -> None:
        first, second = calibration_instances()
        self.assertEqual((first.n, first.q, first.error["stddev"]), (1024, 1 << 32, 11.0))
        self.assertEqual(
            (second.n, second.q, second.error["stddev"]),
            (2048, 66974689739603969, 6.4),
        )
        self.assertEqual(first.m, "infinity")
        self.assertEqual(second.m, "infinity")
        self.assertEqual(first.paper_estimator, "ypir")
        self.assertEqual(second.paper_estimator, "ypir")
        self.assertAlmostEqual(REFERENCE_BITS["ypir-paper-d1"], 128.5072668654386)
        self.assertAlmostEqual(REFERENCE_BITS["ypir-paper-d2"], 131.53965108808902)


if __name__ == "__main__":
    unittest.main()
