"""Parameter derivation and proof-bound checks for the native PIR profiles.

This module deliberately contains no Sage imports.  It can be tested with the
system Python while ``sage_worker.py`` isolates the version-sensitive Lattice
Estimator API.
"""

from __future__ import annotations

import copy
import json
import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


PROFILES = ("baseline", "ypir-main", "distpir-offline", "hybrid")
MAIN_RING_PROFILES = frozenset(("ypir-main", "hybrid"))
OFFLINE_RING_PROFILES = frozenset(("distpir-offline", "hybrid"))

SMALL_CLIENT_COMMIT = "162c505"
YPIR_COMMIT = "4195c66"
MODERN_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"


class ConfigError(ValueError):
    """Raised when an audit configuration is internally inconsistent."""


@dataclass(frozen=True)
class SecurityInstance:
    instance_id: str
    stage: str
    primitive: str
    estimator_problem: str
    n: int
    q: int
    m: int | str
    secret: dict[str, Any] | None
    error: dict[str, Any] | None
    length_bound: int | None
    norm: str | None
    paper_estimator: str
    assumption: str
    conditional: bool = False
    sensitivity: bool = False
    actual_samples: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def worker_spec(self, method: str) -> dict[str, Any]:
        spec: dict[str, Any] = {
            "problem": self.estimator_problem,
            "n": self.n,
            "q": self.q,
            "m": self.m,
            "method": method,
            "tag": self.instance_id,
        }
        if self.estimator_problem == "lwe":
            spec["secret"] = self.secret
            spec["error"] = self.error
        else:
            spec["length_bound"] = self.length_bound
            spec["norm"] = self.norm
        return spec


def load_config(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot load configuration {path}: {exc}") from exc
    validate_config(data)
    return data


def _require_positive_int(mapping: dict[str, Any], key: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{key} must be a positive integer")
    return value


def expand_candidates(value: Any, label: str) -> list[int]:
    if isinstance(value, list):
        candidates = value
    elif isinstance(value, dict):
        start = _require_positive_int(value, "start")
        stop = _require_positive_int(value, "stop")
        step = _require_positive_int(value, "step")
        if stop < start:
            raise ConfigError(f"{label}: stop must be at least start")
        candidates = list(range(start, stop + 1, step))
    else:
        raise ConfigError(f"{label} must be a list or a start/stop/step object")
    if not candidates or any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in candidates):
        raise ConfigError(f"{label} must contain positive integers")
    return sorted(set(candidates))


def is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def validate_config(config: dict[str, Any]) -> None:
    if config.get("schema_version") != 1:
        raise ConfigError("schema_version must be 1")
    for optional_key in ("estimator_timeout_seconds", "estimator_parallel_jobs"):
        if optional_key in config:
            _require_positive_int(config, optional_key)
    if config.get("fhe_attack_profile", "decisive-usvp") not in (
        "decisive-usvp",
        "full",
    ):
        raise ConfigError("fhe_attack_profile must be decisive-usvp or full")

    database = config.get("database")
    parameters = config.get("parameters")
    candidates = config.get("candidates")
    targets = config.get("targets")
    current = config.get("current")
    if not all(isinstance(item, dict) for item in (database, parameters, candidates, targets, current)):
        raise ConfigError("database, parameters, candidates, targets, and current must be objects")

    rows = _require_positive_int(database, "rows")
    columns = _require_positive_int(database, "columns")
    record_bits = _require_positive_int(database, "record_bits")
    _require_positive_int(database, "stack_cells")
    if (rows * columns * record_bits) % 8:
        raise ConfigError("database layout does not represent a whole number of bytes")
    expected_bytes = database.get("logical_bytes")
    actual_bytes = rows * columns * record_bits // 8
    if expected_bytes is not None and expected_bytes != actual_bytes:
        raise ConfigError(
            f"logical_bytes mismatch: layout gives {actual_bytes}, configuration says {expected_bytes}"
        )

    profiles = config.get("profiles", list(PROFILES))
    if not isinstance(profiles, list) or not profiles:
        raise ConfigError("profiles must be a non-empty list")
    unknown = sorted(set(profiles) - set(PROFILES))
    if unknown:
        raise ConfigError(f"unknown profiles: {', '.join(unknown)}")

    for key in ("computational_bits", "correctness_bits", "statistical_bits", "deployment_targets"):
        _require_positive_int(targets, key)
    for key in ("q_main", "q_offline", "plaintext_modulus"):
        _require_positive_int(parameters, key)
    if parameters["plaintext_modulus"] != 1 << record_bits:
        raise ConfigError("plaintext_modulus must equal 2^record_bits for the native encoding")
    if parameters.get("main_error_variance") != 8:
        raise ConfigError("the calibrated main centered-binomial variance must be 8")
    if float(parameters.get("offline_error_stddev", 0)) <= 0:
        raise ConfigError("offline_error_stddev must be positive")

    fhe = parameters.get("fhe")
    if not isinstance(fhe, dict):
        raise ConfigError("parameters.fhe must be an object")
    degree = _require_positive_int(fhe, "ring_degree")
    if not is_power_of_two(degree):
        raise ConfigError("FHE ring degree must be a power of two")
    moduli = fhe.get("moduli")
    if not isinstance(moduli, list) or len(moduli) < 1:
        raise ConfigError("parameters.fhe.moduli must be a non-empty list")
    if any(isinstance(item, bool) or not isinstance(item, int) or item <= 2 for item in moduli):
        raise ConfigError("FHE moduli must be positive integers")
    fhe_plaintext_modulus = _require_positive_int(fhe, "plaintext_modulus")
    if fhe_plaintext_modulus >= min(moduli):
        raise ConfigError("FHE plaintext modulus must be smaller than every ciphertext modulus")
    if (fhe_plaintext_modulus - 1) % (2 * degree):
        raise ConfigError("FHE plaintext modulus is incompatible with the ring degree")
    gadget_log_bases = fhe.get("gadget_log_bases")
    if (
        not isinstance(gadget_log_bases, list)
        or len(gadget_log_bases) != len(moduli)
        or any(
            isinstance(item, bool) or not isinstance(item, int) or item <= 0
            for item in gadget_log_bases
        )
    ):
        raise ConfigError("FHE gadget_log_bases must contain one positive integer per modulus")
    for modulus in moduli:
        if (modulus - 1) % (2 * degree):
            raise ConfigError("FHE ciphertext modulus is incompatible with the ring degree")

    for key in (
        "main_lwe_dimensions",
        "offline_lwe_dimensions",
        "main_ring_degrees",
        "offline_ring_degrees",
    ):
        values = expand_candidates(candidates.get(key), f"candidates.{key}")
        if "ring_degrees" in key and any(not is_power_of_two(item) for item in values):
            raise ConfigError(f"candidates.{key} must contain powers of two")

    runtime_supported = config.get("runtime_supported")
    if runtime_supported is not None:
        if not isinstance(runtime_supported, dict):
            raise ConfigError("runtime_supported must be an object")
        for key in (
            "main_lwe_dimensions",
            "offline_lwe_dimensions",
            "main_ring_degrees",
            "offline_ring_degrees",
        ):
            supported = set(expand_candidates(runtime_supported.get(key), f"runtime_supported.{key}"))
            allowed = set(expand_candidates(candidates.get(key), f"candidates.{key}"))
            if not supported <= allowed:
                raise ConfigError(f"runtime_supported.{key} must be a subset of candidates.{key}")

    q_main = parameters["q_main"]
    q_offline = parameters["q_offline"]
    for degree in expand_candidates(candidates["main_ring_degrees"], "main_ring_degrees"):
        if columns % degree or (q_main - 1) % (2 * degree):
            raise ConfigError(f"main ring degree {degree} is incompatible with columns or q_main")
    for degree in expand_candidates(candidates["offline_ring_degrees"], "offline_ring_degrees"):
        if rows % degree or (q_offline - 1) % (2 * degree):
            raise ConfigError(f"offline ring degree {degree} is incompatible with rows or q_offline")

    for key in ("main_lwe_dimension", "offline_lwe_dimension", "main_ring_degree", "offline_ring_degree"):
        _require_positive_int(current, key)
    if not is_power_of_two(current["main_ring_degree"]) or not is_power_of_two(
        current["offline_ring_degree"]
    ):
        raise ConfigError("current ring degrees must be powers of two")
    if columns % current["main_ring_degree"] or (q_main - 1) % (2 * current["main_ring_degree"]):
        raise ConfigError("current main ring degree is incompatible with columns or q_main")
    if rows % current["offline_ring_degree"] or (
        q_offline - 1
    ) % (2 * current["offline_ring_degree"]):
        raise ConfigError("current offline ring degree is incompatible with rows or q_offline")


def logical_database_bytes(config: dict[str, Any]) -> int:
    database = config["database"]
    return database["rows"] * database["columns"] * database["record_bits"] // 8


def human_binary_size(size: int) -> str:
    for suffix, scale in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if size % scale == 0 and size >= scale:
            return f"{size // scale} {suffix}"
    return f"{size} B"


def _ternary() -> dict[str, Any]:
    return {"kind": "uniform", "a": -1, "b": 1}


def _centered_binomial_variance_8() -> dict[str, Any]:
    # Lattice Estimator uses stddev=sqrt(eta/2), hence eta=16 for variance 8.
    return {"kind": "centered_binomial", "eta": 16}


def _discrete_gaussian(stddev: float) -> dict[str, Any]:
    return {"kind": "discrete_gaussian", "stddev": float(stddev)}


def honest_h_sis_bound(config: dict[str, Any]) -> dict[str, int]:
    rows = config["database"]["rows"]
    plaintext_modulus = config["parameters"]["plaintext_modulus"]
    proof_bound = rows * plaintext_modulus
    database_bound = plaintext_modulus - 1
    infinity_bound = proof_bound + rows * database_bound
    return {
        "proof_bound_B": proof_bound,
        "database_infinity_bound": database_bound,
        "sis_infinity_bound": infinity_bound,
    }


def main_instances(config: dict[str, Any], kind: str, dimension: int) -> list[SecurityInstance]:
    database = config["database"]
    parameters = config["parameters"]
    samples = database["columns"]
    q = parameters["q_main"]
    sis_bound = honest_h_sis_bound(config)["sis_infinity_bound"]
    prefix = f"main-{kind}-{dimension}"

    if kind == "dense":
        return [
            SecurityInstance(
                instance_id=f"{prefix}-lwe-actual",
                stage="main",
                primitive="LWE",
                estimator_problem="lwe",
                n=dimension,
                q=q,
                m=samples,
                secret=_ternary(),
                error=_centered_binomial_variance_8(),
                length_bound=None,
                norm=None,
                paper_estimator="small-client",
                assumption="LWE",
                actual_samples=samples,
            ),
            SecurityInstance(
                instance_id=f"{prefix}-lwe-unbounded",
                stage="main",
                primitive="LWE",
                estimator_problem="lwe",
                n=dimension,
                q=q,
                m="infinity",
                secret=_ternary(),
                error=_centered_binomial_variance_8(),
                length_bound=None,
                norm=None,
                paper_estimator="small-client",
                assumption="LWE with unlimited-sample sensitivity",
                sensitivity=True,
                actual_samples=samples,
            ),
            SecurityInstance(
                instance_id=f"{prefix}-sis",
                stage="commitment",
                primitive="SIS",
                estimator_problem="sis",
                n=dimension,
                q=q,
                m=samples,
                secret=None,
                error=None,
                length_bound=sis_bound,
                norm="infinity",
                paper_estimator="small-client",
                assumption="SIS under the honest-H bound",
                actual_samples=samples,
            ),
        ]

    if kind != "ring":
        raise ConfigError(f"unknown main kind: {kind}")
    return [
        SecurityInstance(
            instance_id=f"{prefix}-rlwe-actual",
            stage="main",
            primitive="RLWE",
            estimator_problem="lwe",
            n=dimension,
            q=q,
            m=samples,
            secret=_ternary(),
            error=_centered_binomial_variance_8(),
            length_bound=None,
            norm=None,
            paper_estimator="ypir",
            assumption="negacyclic RLWE, coefficient embedding",
            actual_samples=samples,
        ),
        SecurityInstance(
            instance_id=f"{prefix}-rlwe-unbounded",
            stage="main",
            primitive="RLWE",
            estimator_problem="lwe",
            n=dimension,
            q=q,
            m="infinity",
            secret=_ternary(),
            error=_centered_binomial_variance_8(),
            length_bound=None,
            norm=None,
            paper_estimator="ypir",
            assumption="negacyclic RLWE with unlimited-sample sensitivity",
            sensitivity=True,
            actual_samples=samples,
        ),
        SecurityInstance(
            instance_id=f"{prefix}-ring-sis",
            stage="commitment",
            primitive="Ring/Module-SIS",
            estimator_problem="sis",
            n=dimension,
            q=q,
            m=samples,
            secret=None,
            error=None,
            length_bound=sis_bound,
            norm="infinity",
            paper_estimator="small-client",
            assumption="generic SIS scalarization of structured Ring/Module-SIS",
            conditional=True,
            actual_samples=samples,
        ),
    ]


def offline_instances(config: dict[str, Any], kind: str, dimension: int) -> list[SecurityInstance]:
    database = config["database"]
    parameters = config["parameters"]
    samples = database["rows"]
    q = parameters["q_offline"]
    error = _discrete_gaussian(parameters["offline_error_stddev"])
    prefix = f"offline-{kind}-{dimension}"

    if kind == "dense":
        return [
            SecurityInstance(
                instance_id=f"{prefix}-lwe-actual",
                stage="offline",
                primitive="LWE",
                estimator_problem="lwe",
                n=dimension,
                q=q,
                m=samples,
                secret=_ternary(),
                error=error,
                length_bound=None,
                norm=None,
                paper_estimator="small-client",
                assumption="LWE for encrypted offline challenges",
                actual_samples=samples,
            ),
            SecurityInstance(
                instance_id=f"{prefix}-lwe-unbounded",
                stage="offline",
                primitive="LWE",
                estimator_problem="lwe",
                n=dimension,
                q=q,
                m="infinity",
                secret=_ternary(),
                error=error,
                length_bound=None,
                norm=None,
                paper_estimator="small-client",
                assumption="LWE with unlimited-sample sensitivity",
                sensitivity=True,
                actual_samples=samples,
            ),
        ]

    if kind != "ring":
        raise ConfigError(f"unknown offline kind: {kind}")
    return [
        SecurityInstance(
            instance_id=f"{prefix}-rlwe-actual",
            stage="offline",
            primitive="RLWE",
            estimator_problem="lwe",
            n=dimension,
            q=q,
            m=samples,
            secret=_ternary(),
            error=error,
            length_bound=None,
            norm=None,
            paper_estimator="ypir",
            assumption="negacyclic RLWE, coefficient embedding",
            actual_samples=samples,
        ),
        SecurityInstance(
            instance_id=f"{prefix}-rlwe-unbounded",
            stage="offline",
            primitive="RLWE",
            estimator_problem="lwe",
            n=dimension,
            q=q,
            m="infinity",
            secret=_ternary(),
            error=error,
            length_bound=None,
            norm=None,
            paper_estimator="ypir",
            assumption="negacyclic RLWE with unlimited-sample sensitivity",
            sensitivity=True,
            actual_samples=samples,
        ),
    ]


def common_instances(config: dict[str, Any]) -> list[SecurityInstance]:
    fhe = config["parameters"]["fhe"]
    modulus = math.prod(fhe["moduli"])
    return [
        SecurityInstance(
            instance_id="fhe-bfv-rlwe-unbounded",
            stage="query-preparation",
            primitive="BFV/RLWE",
            estimator_problem="lwe",
            n=fhe["ring_degree"],
            q=modulus,
            m="infinity",
            secret=_centered_binomial_variance_8(),
            error=_centered_binomial_variance_8(),
            length_bound=None,
            norm=None,
            paper_estimator="small-client",
            assumption="BFV RLWE and circular/KDM security for evaluation keys",
        )
    ]


def profile_kinds(profile: str) -> tuple[str, str]:
    if profile not in PROFILES:
        raise ConfigError(f"unknown profile: {profile}")
    main_kind = "ring" if profile in MAIN_RING_PROFILES else "dense"
    offline_kind = "ring" if profile in OFFLINE_RING_PROFILES else "dense"
    return main_kind, offline_kind


def candidate_values(config: dict[str, Any], stage: str, kind: str, runtime_only: bool = False) -> list[int]:
    key = f"{stage}_{'ring_degrees' if kind == 'ring' else 'lwe_dimensions'}"
    source = config.get("runtime_supported", {}) if runtime_only else config["candidates"]
    raw = source.get(key)
    if raw is None and runtime_only:
        raw = config["candidates"][key]
    return expand_candidates(raw, f"{'runtime_supported' if runtime_only else 'candidates'}.{key}")


def current_dimension(config: dict[str, Any], stage: str, kind: str) -> int:
    key = f"{stage}_{'ring_degree' if kind == 'ring' else 'lwe_dimension'}"
    return int(config["current"][key])


def _tail_log2_delta(q: int, scale_without_sqrt_m: float, sample_count: int) -> float:
    ratio = float(q) / (scale_without_sqrt_m * math.sqrt(sample_count))
    return 1.0 - ratio * ratio / (2.0 * math.log(2.0))


def correctness_analysis(config: dict[str, Any]) -> dict[str, Any]:
    database = config["database"]
    parameters = config["parameters"]
    targets = config["targets"]
    rows = database["rows"]
    columns = database["columns"]
    record_bound = 1 << database["record_bits"]
    plaintext_modulus = parameters["plaintext_modulus"]
    main_sigma = math.sqrt(float(parameters["main_error_variance"]))
    offline_sigma = float(parameters["offline_error_stddev"])

    main_scale = main_sigma * plaintext_modulus * record_bound
    offline_scale = offline_sigma * plaintext_modulus * record_bound * 2 * rows
    main_raw = _tail_log2_delta(parameters["q_main"], main_scale, columns)
    offline_raw = _tail_log2_delta(parameters["q_offline"], offline_scale, columns)

    main_union = main_raw + math.log2(database["stack_cells"])
    offline_union = offline_raw + math.log2(targets["statistical_bits"] * columns)
    largest = max(main_union, offline_union)
    strict_union = largest + math.log2(
        2 ** (main_union - largest) + 2 ** (offline_union - largest)
    ) + math.log2(targets["deployment_targets"])

    fhe = parameters["fhe"]
    validated_fhe = (
        fhe["ring_degree"] == 4096
        and fhe["moduli"] == [19988226643746817, 19988226643402753]
        and fhe.get("plaintext_modulus") == 4278255617
        and fhe.get("gadget_log_bases") == [13, 14]
        and fhe.get("error_variance") == 8
        and rows % 2048 == 0
    )
    target = -float(targets["correctness_bits"])
    passed = main_raw <= target and offline_raw <= target and strict_union <= target and validated_fhe
    return {
        "status": "pass" if passed else "fail",
        "target_log2_failure": target,
        "main_log2_failure_bound": main_raw,
        "offline_log2_failure_bound": offline_raw,
        "strict_union_log2_failure_bound": strict_union,
        "fhe_correctness": "validated-per-response-block-bfv-profile" if validated_fhe else "not-calibrated",
        "fhe_response_blocks": rows // 2048,
        "scope_note": (
            "The numeric union bound covers the native main/offline LHE checks. "
            "BFV correctness is tied to the dedicated per-response-block "
            "bfv_parameters_test target; the database profile records the total block count."
        ),
    }


def inspect_runtime_source(project_root: Path) -> dict[str, int]:
    source_root = project_root / "native/vendor/Verifiable-Hintless-PIR"
    test_source = source_root / "hintless_simplepir/new_pir_test.cc"
    utility_header = source_root / "verisimplepir/src/lib/pir/utils.h"
    try:
        test_text = test_source.read_text(encoding="utf-8")
        utility_text = utility_header.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot inspect current native source: {exc}") from exc

    def capture(text: str, pattern: str, label: str) -> int:
        match = re.search(pattern, text, flags=re.MULTILINE)
        if not match:
            raise ConfigError(f"cannot find {label} in current native source")
        return int(match.group(1))

    def capture_active_modulus(text: str, macro: str) -> int:
        # utils.h retains zero-valued fallback definitions in inactive #if
        # branches.  The production modulus is the unique non-zero maximum.
        values = [
            int(value)
            for value in re.findall(
                rf"^#define\s+{re.escape(macro)}\s+(\d+)ULL", text, flags=re.MULTILINE
            )
        ]
        nonzero = [value for value in values if value > 0]
        if not nonzero:
            raise ConfigError(f"cannot find active {macro} in current native source")
        return max(nonzero)

    moduli_match = re.search(r"\.qs\s*=\s*\{(\d+)ULL,\s*(\d+)ULL\}", test_text)
    if not moduli_match:
        raise ConfigError("cannot find BFV moduli in current native source")
    gadget_match = re.search(r"\.gadget_log_bs\s*=\s*\{(\d+),\s*(\d+)\}", test_text)
    if not gadget_match:
        raise ConfigError("cannot find BFV gadget bases in current native source")
    if re.search(r"^#define\s+SH_RUN(?:\s|$)", utility_text, flags=re.MULTILINE):
        raise ConfigError("source-derived BFV plaintext modulus is not supported with SH_RUN enabled")
    q_main = capture_active_modulus(utility_text, "SOL_NTT_PRIME")
    return {
        "rows": capture(test_text, r"^const int rows_db\s*=\s*(\d+);", "rows_db"),
        "columns": capture(test_text, r"^const int cols_db\s*=\s*(\d+);", "cols_db"),
        "stack_cells": capture(test_text, r"\.db_stack_cells\s*=\s*(\d+),", "db_stack_cells"),
        "record_bits": capture(test_text, r"\.db_record_bit_size\s*=\s*(\d+),", "db_record_bit_size"),
        "plaintext_bits": capture(
            test_text, r"\.lwe_plaintext_bit_size\s*=\s*(\d+),", "lwe_plaintext_bit_size"
        ),
        "main_lwe_dimension": capture(test_text, r"\.lwe_secret_dim\s*=\s*(\d+),", "lwe_secret_dim"),
        "offline_lwe_dimension": capture(
            test_text, r"\.offline_lwe_secret_dim\s*=\s*(\d+),", "offline_lwe_secret_dim"
        ),
        "q_main": q_main,
        "q_offline": capture_active_modulus(utility_text, "VSPIR_LHE_PRIME"),
        "main_ring_degree": (
            1
            << capture(test_text, r"constexpr int kYpirRingLogN\s*=\s*(\d+);", "kYpirRingLogN")
        ),
        "offline_ring_degree": capture(
            test_text,
            r"^\s*int offline_ring_degree\s*=\s*(\d+);",
            "default offline_ring_degree",
        ),
        "fhe_ring_degree": 1 << capture(test_text, r"\.log_n\s*=\s*(\d+),", "BFV log_n"),
        "fhe_modulus_0": int(moduli_match.group(1)),
        "fhe_modulus_1": int(moduli_match.group(2)),
        "fhe_plaintext_modulus": q_main,
        "fhe_gadget_log_base_0": int(gadget_match.group(1)),
        "fhe_gadget_log_base_1": int(gadget_match.group(2)),
    }


def config_from_current_source(config: dict[str, Any], project_root: Path) -> dict[str, Any]:
    runtime = inspect_runtime_source(project_root)
    result = copy.deepcopy(config)
    # Database dimensions are selected by --database-profile at runtime.  The
    # size-specific audit config is therefore authoritative; source inspection
    # only freezes cryptographic constants and the legacy default smoke shape.
    result["current"]["main_lwe_dimension"] = runtime["main_lwe_dimension"]
    result["current"]["offline_lwe_dimension"] = runtime["offline_lwe_dimension"]
    result["current"]["main_ring_degree"] = runtime["main_ring_degree"]
    result["current"]["offline_ring_degree"] = runtime["offline_ring_degree"]
    result["parameters"]["q_main"] = runtime["q_main"]
    result["parameters"]["q_offline"] = runtime["q_offline"]
    result["parameters"]["plaintext_modulus"] = 1 << runtime["plaintext_bits"]
    result["parameters"]["fhe"]["ring_degree"] = runtime["fhe_ring_degree"]
    result["parameters"]["fhe"]["moduli"] = [runtime["fhe_modulus_0"], runtime["fhe_modulus_1"]]
    result["parameters"]["fhe"]["plaintext_modulus"] = runtime["fhe_plaintext_modulus"]
    result["parameters"]["fhe"]["gadget_log_bases"] = [
        runtime["fhe_gadget_log_base_0"],
        runtime["fhe_gadget_log_base_1"],
    ]
    result["runtime_source"] = runtime
    validate_config(result)
    return result


def profile_instances(
    config: dict[str, Any], profile: str, main_dimension: int, offline_dimension: int
) -> list[SecurityInstance]:
    main_kind, offline_kind = profile_kinds(profile)
    return (
        common_instances(config)
        + main_instances(config, main_kind, main_dimension)
        + offline_instances(config, offline_kind, offline_dimension)
    )


def minimum_finite(values: Iterable[float | None]) -> float | None:
    finite = [value for value in values if value is not None and math.isfinite(value)]
    return min(finite) if finite else None
