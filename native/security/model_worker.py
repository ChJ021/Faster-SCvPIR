#!/usr/bin/env python3
"""Run one version-pinned Lattice Estimator request under SageMath."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import math
import sys
import traceback
from pathlib import Path
from typing import Any


def distribution(nd: Any, spec: dict[str, Any]) -> Any:
    kind = spec["kind"]
    if kind == "uniform":
        return nd.Uniform(int(spec["a"]), int(spec["b"]))
    if kind == "centered_binomial":
        return nd.CenteredBinomial(int(spec["eta"]))
    if kind == "discrete_gaussian":
        return nd.DiscreteGaussian(float(spec["stddev"]))
    raise ValueError(f"unsupported distribution: {kind}")


def rop_bits(value: Any, infinity: Any, log: Any) -> float | None:
    if value is None or value == infinity:
        return None
    bits = float(log(value, 2))
    return bits if math.isfinite(bits) else None


def json_cost_value(value: Any, infinity: Any) -> Any:
    try:
        if bool(value == infinity):
            return "infinity"
    except (TypeError, ValueError):
        pass
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    try:
        numeric = float(value)
        return numeric if math.isfinite(numeric) else str(value)
    except (TypeError, ValueError, OverflowError):
        return str(value)


def required_attack_families(
    problem: str, method: str, attack_profile: str
) -> list[set[str]]:
    if problem == "sis":
        return [{"lattice"}]
    if attack_profile == "decisive-usvp":
        return [{"usvp"}]
    if method == "rough":
        return [{"usvp"}, {"dual_hybrid", "dual_mitm_hybrid"}]
    return [
        {"usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid"},
        {"dual", "dual_hybrid", "dual_mitm_hybrid"},
    ]


def run_request(estimator_directory: Path, request: dict[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(estimator_directory))
    from estimator import LWE, ND, SIS  # type: ignore  # pylint: disable=import-outside-toplevel
    from sage.all import log, oo  # type: ignore  # pylint: disable=import-outside-toplevel

    problem = request["problem"]
    method = request.get("method", "full")
    attack_profile = request.get("attack_profile", "full")
    if attack_profile not in ("full", "decisive-usvp", "paper-lattice"):
        raise ValueError(f"unsupported attack profile: {attack_profile}")
    if method != "full" and attack_profile != "full":
        raise ValueError("a reduced attack profile is only valid with method=full")
    estimate_kwargs: dict[str, Any] = {}
    m = oo if request["m"] == "infinity" else int(request["m"])
    if problem == "lwe":
        params = LWE.Parameters(
            n=int(request["n"]),
            q=int(request["q"]),
            Xs=distribution(ND, request["secret"]),
            Xe=distribution(ND, request["error"]),
            m=m,
            tag=request.get("tag"),
        )
        estimate = LWE.estimate.rough if method == "rough" else LWE.estimate
        if attack_profile == "paper-lattice":
            from estimator.reduction import RC
            # Explicit, fixed model; not a search over cost conventions.
            estimate_kwargs.update(red_cost_model=RC.MATZOV,
                                   red_shape_model="gsa",
                                   deny_list=("arora-gb", "bkw"))
        if attack_profile == "decisive-usvp":
            estimate_kwargs["deny_list"] = (
                "arora-gb",
                "bkw",
                "bdd",
                "bdd_hybrid",
                "bdd_mitm_hybrid",
                "dual",
                "dual_hybrid",
                "dual_mitm_hybrid",
            )
    elif problem == "sis":
        norm = oo if request["norm"] == "infinity" else int(request["norm"])
        params = SIS.Parameters(
            n=int(request["n"]),
            q=int(request["q"]),
            length_bound=int(request["length_bound"]),
            m=int(request["m"]),
            norm=norm,
            tag=request.get("tag"),
        )
        # The pinned estimator's default SIS cost model returns only an
        # infinite sentinel for this honest-H infinity-norm regime.  Its rough
        # Core-SVP lattice routine is the finite SIS estimator recommended for
        # comparable parameter selection, so use it in both CLI modes.
        estimate = SIS.estimate.rough
    else:
        raise ValueError(f"unsupported estimator problem: {problem}")

    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    with contextlib.redirect_stdout(captured_stdout), contextlib.redirect_stderr(captured_stderr):
        result = estimate(params, jobs=1, catch_exceptions=False, **estimate_kwargs)

    attacks: dict[str, dict[str, Any]] = {}
    for name, cost in result.items():
        bits = rop_bits(cost.get("rop"), oo, log)
        attacks[str(name)] = {
            "rop_bits": bits,
            "rop_infinite": bool(cost.get("rop") == oo),
            "cost": {str(key): json_cost_value(value, oo) for key, value in cost.items()},
        }

    present_attacks = set(attacks)
    missing_families = [
        sorted(family)
        for family in required_attack_families(problem, method, attack_profile)
        if not family & present_attacks
    ]
    finite_bits = [value["rop_bits"] for value in attacks.values() if value["rop_bits"] is not None]
    if attack_profile == "paper-lattice":
        required = {"lattice"} if problem == "sis" else {
            "usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid", "dual", "dual_hybrid"
        }
        # The YPIR snapshot has one additional, separately named dual attack.
        if problem == "lwe" and estimator_directory.name.endswith("4195c66"):
            required.add("dual_mitm_hybrid")
        missing_families = [[name] for name in sorted(required - present_attacks)]
        invalid = [name for name in required & present_attacks
                   if attacks[name]["rop_bits"] is None]
    else:
        invalid = []
    status = "ok" if finite_bits and not missing_families and not invalid else "error"
    response: dict[str, Any] = {
        "status": status,
        "problem": problem,
        "method": method,
        "method_applied": "rough" if problem == "sis" else method,
        "attack_profile": attack_profile,
        "complete_attack_suite": problem == "sis" or attack_profile == "full",
        "complete_declared_profile": status == "ok",
        "invalid_attacks": invalid,
        "cost_model": "ADPS16/Core-SVP; LGSA" if problem == "sis" else "MATZOV; GSA",
        "minimum_rop_bits": min(finite_bits) if finite_bits else None,
        "weakest_attack": min(
            (name for name in attacks if attacks[name]["rop_bits"] is not None),
            key=lambda name: attacks[name]["rop_bits"],
            default=None,
        ),
        "attacks": attacks,
        "missing_attack_families": missing_families,
    }
    if status != "ok":
        diagnostics = (captured_stdout.getvalue() + "\n" + captured_stderr.getvalue()).strip()
        response["diagnostic_tail"] = diagnostics[-4000:]
    return response


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--estimator", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()
    try:
        request = json.loads(args.input.read_text(encoding="utf-8"))
        response = run_request(args.estimator, request)
    except Exception as exc:  # Fail closed and return structured diagnostics.
        response = {
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "diagnostic_tail": traceback.format_exc()[-4000:],
        }
    print(json.dumps(response, sort_keys=True, allow_nan=False))
    return 0 if response["status"] == "ok" else 3


if __name__ == "__main__":
    raise SystemExit(main())
