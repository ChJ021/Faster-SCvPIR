"""Fast regression tests; estimator execution itself requires SageMath."""
import copy
import json
import math
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from model_audit import assessment, instances
from model_worker import run_request


class ModelAuditTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((Path(__file__).parent / "configs/1gib.json").read_text())

    def test_fail_closed(self):
        self.assertEqual(assessment({}), "INCONCLUSIVE")
        self.assertEqual(assessment({"status": "ok", "minimum_rop_bits": 150}), "INCONCLUSIVE")
        for bits in (None, math.inf, math.nan):
            self.assertEqual(assessment({"status": "ok", "complete_declared_profile": True,
                                         "minimum_rop_bits": bits}), "INCONCLUSIVE")

    def test_threshold(self):
        for bits, expected in ((127.99, "FAIL"), (128, "PASS-IN-MODEL")):
            self.assertEqual(assessment({"status": "ok", "complete_declared_profile": True,
                                         "minimum_rop_bits": bits}), expected)

    def test_requests_match_paper(self):
        values = {name: (pin, spec) for name, pin, spec in instances(self.config)}
        self.assertEqual(len(values), 7)
        self.assertEqual(values["dense-main"][1]["error"]["eta"], 16)
        self.assertEqual(values["structured-main"][1]["n"], 2048)
        self.assertEqual(values["structured-offline"][1]["n"], 4096)
        self.assertEqual(values["dense-binding"][1]["length_bound"], 16744448)
        self.assertEqual(values["bfv"][1]["q"], 399529204354912915151294292787201)
        self.assertEqual(values["bfv"][1]["m"], "infinity")

    def test_asymmetric_layout_sample_counts(self):
        config = copy.deepcopy(self.config)
        config["database"]["columns"] = 16384
        values = {name: spec for name, _, spec in instances(config)}
        self.assertEqual(values["dense-main"]["m"], 16384)
        self.assertEqual(values["dense-offline"]["m"], 32768)
        self.assertEqual(values["dense-binding"]["m"], 16384)

    def test_reject_unsupported_variance_and_multi_target(self):
        self.config["parameters"]["main_error_variance"] = 16
        with self.assertRaises(ValueError):
            list(instances(self.config))
        self.config["parameters"]["main_error_variance"] = 8
        self.config["targets"]["deployment_targets"] = 2
        with self.assertRaises(ValueError):
            list(instances(self.config))

    def fake_worker(self, attacks, snapshot="162c505"):
        estimate = Mock(return_value=attacks)
        nd = SimpleNamespace(Uniform=lambda *args: None, CenteredBinomial=lambda *args: None)
        modules = {
            "estimator": SimpleNamespace(LWE=SimpleNamespace(Parameters=lambda **kw: kw,
                                                             estimate=estimate), ND=nd, SIS=None),
            "estimator.reduction": SimpleNamespace(RC=SimpleNamespace(MATZOV="MATZOV")),
            "sage.all": SimpleNamespace(log=math.log, oo=math.inf),
        }
        request = next(spec for name, _, spec in instances(self.config) if name == "dense-main")
        with patch.dict("sys.modules", modules):
            result = run_request(Path(f"lattice-estimator-{snapshot}"), request)
        self.assertFalse(estimate.call_args.kwargs["catch_exceptions"])
        self.assertEqual(estimate.call_args.kwargs["deny_list"], ("arora-gb", "bkw"))
        return result

    def test_every_declared_attack_required(self):
        names = ("usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid", "dual", "dual_hybrid")
        attacks = {name: {"rop": 2**140} for name in names}
        self.assertEqual(self.fake_worker(attacks)["status"], "ok")
        for name in names:
            partial = dict(attacks)
            del partial[name]
            self.assertEqual(self.fake_worker(partial)["status"], "error")
        self.assertEqual(self.fake_worker(attacks, "4195c66")["status"], "error")

    def test_infinite_attack_not_silently_ignored(self):
        names = ("usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid", "dual", "dual_hybrid")
        attacks = {name: {"rop": 2**140} for name in names}
        attacks["bdd"] = {"rop": math.inf}
        self.assertEqual(self.fake_worker(attacks)["status"], "error")


if __name__ == "__main__":
    unittest.main()
