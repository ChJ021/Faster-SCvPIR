"""Parameter profiles and the no-publisher reparameterization gate."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROFILE_SCHEMA = "small-client-vpir-parameters-v2"


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_security_score(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def _ceil_log2_positive(value: int) -> int:
    """Return ``ceil(log2(value))`` exactly for a positive integer."""

    if not _is_int(value) or value <= 0:
        raise ValueError("multi-target count must be a positive integer")
    return (value - 1).bit_length()


def _is_probable_prime_64(value: int) -> bool:
    if value < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if value in small_primes:
        return True
    if any(value % prime == 0 for prime in small_primes):
        return False
    exponent, odd = 0, value - 1
    while odd % 2 == 0:
        exponent += 1
        odd //= 2
    # Deterministic for unsigned 64-bit integers.
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % value == 0:
            continue
        witness = pow(base, odd, value)
        if witness in (1, value - 1):
            continue
        for _ in range(exponent - 1):
            witness = pow(witness, 2, value)
            if witness == value - 1:
                break
        else:
            return False
    return True


@dataclass(frozen=True)
class SecurityEvidence:
    lifetime_target_bits: int | None = None
    query_lwe_single_instance_bits: float | None = None
    registration_lhe_single_instance_bits: float | None = None
    hint_fhe_rlwe_single_instance_bits: float | None = None
    sis_general_bound_single_instance_bits: float | None = None
    estimator_commit: str | None = None
    artifact_sha256: str | None = None
    public_matrix_seed_source: str | None = None
    setup_transcript_sha256: str | None = None
    query_error_tail_bound_id: str | None = None
    query_error_tail_artifact_sha256: str | None = None
    query_secret_min_entropy_bits: float | None = None
    query_feedback_leakage_bits: int | None = None
    leaky_secret_argument_id: str | None = None
    leaky_secret_artifact_sha256: str | None = None

    @classmethod
    def from_mapping(cls, value: dict[str, Any] | None) -> "SecurityEvidence":
        if value is None:
            return cls()
        if not isinstance(value, dict):
            raise ValueError("security_evidence must be an object")
        allowed = set(cls.__dataclass_fields__)
        if set(value) - allowed:
            raise ValueError("security_evidence has unexpected fields")
        return cls(**value)


@dataclass(frozen=True)
class PrimitiveContextParameters:
    role: str
    scheme: str
    status: str
    dimension: int | None
    plaintext_modulus: int | None
    ciphertext_moduli_bits: tuple[int, ...]
    secret_distribution: str | None
    error_distribution: str | None
    error_parameter: float | None

    @classmethod
    def from_mapping(cls, value: Any, *, expected_role: str) -> "PrimitiveContextParameters":
        if not isinstance(value, dict):
            raise ValueError(f"{expected_role} context must be an object")
        allowed = set(cls.__dataclass_fields__)
        if set(value) != allowed:
            raise ValueError(f"{expected_role} context fields are incomplete or unexpected")
        data = dict(value)
        moduli = data.get("ciphertext_moduli_bits")
        if not isinstance(moduli, list) or any(not _is_int(item) or item <= 0 for item in moduli):
            raise ValueError(f"{expected_role} ciphertext_moduli_bits must be positive integers")
        data["ciphertext_moduli_bits"] = tuple(moduli)
        context = cls(**data)
        context.validate(expected_role=expected_role)
        return context

    def validate(self, *, expected_role: str) -> None:
        if self.role != expected_role:
            raise ValueError(f"primitive context role must be {expected_role}")
        if not isinstance(self.scheme, str) or not self.scheme:
            raise ValueError("primitive context scheme must be non-empty")
        if self.status not in {"reference-only", "unvalidated", "selected"}:
            raise ValueError("primitive context status is invalid")
        for value in (self.dimension, self.plaintext_modulus):
            if value is not None and (not _is_int(value) or value <= 0):
                raise ValueError("primitive context numeric fields must be positive")
        if any(not _is_int(item) or item <= 0 for item in self.ciphertext_moduli_bits):
            raise ValueError("ciphertext modulus bit widths must be positive")
        if self.error_parameter is not None and not _is_security_score(self.error_parameter):
            raise ValueError("primitive context error_parameter must be finite and non-negative")

    @property
    def complete_and_selected(self) -> bool:
        return (
            self.status == "selected"
            and self.dimension is not None
            and self.plaintext_modulus is not None
            and bool(self.ciphertext_moduli_bits)
            and isinstance(self.secret_distribution, str)
            and bool(self.secret_distribution)
            and isinstance(self.error_distribution, str)
            and bool(self.error_distribution)
            and self.error_parameter is not None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "scheme": self.scheme,
            "status": self.status,
            "dimension": self.dimension,
            "plaintext_modulus": self.plaintext_modulus,
            "ciphertext_moduli_bits": list(self.ciphertext_moduli_bits),
            "secret_distribution": self.secret_distribution,
            "error_distribution": self.error_distribution,
            "error_parameter": self.error_parameter,
        }

    @property
    def digest_hex(self) -> str:
        encoded = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class AuditCheck:
    name: str
    passed: bool
    blocking: bool
    detail: str


@dataclass(frozen=True)
class ComputationalSecurityLedgerEntry:
    primitive: str
    single_instance_estimate_bits: float | None
    lifetime_target_bits: int | None
    lifetime_target_count: int
    multi_target_margin_bits: int
    required_single_instance_bits_for_lifetime: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "single_instance_estimate_bits": self.single_instance_estimate_bits,
            "lifetime_target_bits": self.lifetime_target_bits,
            "lifetime_target_count": self.lifetime_target_count,
            "multi_target_margin_bits": self.multi_target_margin_bits,
            "required_single_instance_bits_for_lifetime": (
                self.required_single_instance_bits_for_lifetime
            ),
        }


@dataclass(frozen=True)
class ParameterAudit:
    profile_name: str
    protocol_variant: str
    max_queries_per_registration: int
    max_registrations_per_client_lifetime: int
    general_sis_beta: int
    honest_hint_beta_for_comparison: int
    correctness_required_q: int
    cumulative_correctness_failure_bound: float
    cumulative_statistical_failure_bound: float
    compression_rows: int
    lifetime_target_bits: int | None
    computational_security_ledger: tuple[ComputationalSecurityLedgerEntry, ...]
    checks: tuple[AuditCheck, ...]

    @property
    def production_ready(self) -> bool:
        return all(check.passed for check in self.checks if check.blocking)

    @property
    def blockers(self) -> tuple[str, ...]:
        return tuple(check.detail for check in self.checks if check.blocking and not check.passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "protocol_variant": self.protocol_variant,
            "max_queries_per_registration": self.max_queries_per_registration,
            "max_registrations_per_client_lifetime": self.max_registrations_per_client_lifetime,
            "general_sis_beta": self.general_sis_beta,
            "honest_hint_beta_for_comparison_only": self.honest_hint_beta_for_comparison,
            "correctness_required_q": self.correctness_required_q,
            "cumulative_correctness_failure_bound": self.cumulative_correctness_failure_bound,
            "cumulative_statistical_failure_bound": self.cumulative_statistical_failure_bound,
            "compression_rows": self.compression_rows,
            "lifetime_target_bits": self.lifetime_target_bits,
            "computational_security_ledger": {
                entry.primitive: entry.to_dict()
                for entry in self.computational_security_ledger
            },
            "production_ready": self.production_ready,
            "checks": [check.__dict__ for check in self.checks],
            "blockers": list(self.blockers),
        }


@dataclass(frozen=True)
class ProtocolParameters:
    name: str
    profile_kind: str
    protocol_variant: str
    plaintext_modulus: int
    ciphertext_modulus: int
    database_rows: int
    database_columns: int
    lwe_dimension: int
    statistical_security_bits: int
    proof_norm_bound: int
    error_sigma: float
    query_secret_distribution: str
    query_error_distribution: str
    registration_lhe: PrimitiveContextParameters
    hint_fhe: PrimitiveContextParameters
    correctness_delta: float
    max_queries_per_registration: int
    max_registrations_per_client_lifetime: int
    correctness_budget_bits: int
    statistical_failure_budget_bits: int
    public_matrix_seed_hex: str
    security_evidence: SecurityEvidence = SecurityEvidence()
    schema: str = PROFILE_SCHEMA

    @property
    def p(self) -> int:
        return self.plaintext_modulus

    @property
    def q(self) -> int:
        return self.ciphertext_modulus

    @property
    def ell(self) -> int:
        return self.database_rows

    @property
    def m(self) -> int:
        return self.database_columns

    @property
    def n(self) -> int:
        return self.lwe_dimension

    @property
    def kappa(self) -> int:
        return self.statistical_security_bits

    @property
    def gamma(self) -> int:
        return math.ceil(self.kappa / math.log2(self.q))

    @property
    def general_sis_beta(self) -> int:
        # Theorem 3.11, required when H is not externally authenticated as honest.
        return (2 * self.ell + 1) * self.proof_norm_bound

    @property
    def provisional_statistical_failure_per_query(self) -> float:
        # Necessary accounting proxy only: Lemma-2.4 scale plus compression.
        # The native security ledger must additionally account for extraction,
        # registration retries, adaptivity and all theorem reductions.
        return 2 ** (-self.kappa + 2) + self.q ** (-self.gamma)

    @property
    def honest_hint_beta_for_comparison(self) -> int:
        # The paper's footnote-8 optimization, shown only to prevent accidental use.
        database_entry_bound = self.p - 1
        return self.proof_norm_bound + self.ell * database_entry_bound

    @property
    def correctness_required_q(self) -> int:
        # Subgaussian tail form matching Lemma A.2, with transformation
        # infinity norm 2B.  The sampler identifier must bind the meaning of
        # error_sigma; production profiles additionally require an artifact.
        value = (
            self.p
            * self.error_sigma
            * (2 * self.proof_norm_bound)
            * math.sqrt(2 * self.m * math.log(2 / self.correctness_delta))
        )
        return math.ceil(value)

    @property
    def computational_security_ledger(
        self,
    ) -> tuple[ComputationalSecurityLedgerEntry, ...]:
        """Conservatively union-bound computational targets over one client life.

        Query LWE, per-query hint FHE/RLWE, and SIS verification attempts are
        counted once for every allowed query across every registration.  The
        registration LHE is counted once per registration.  These counts are
        deliberately conservative; a tighter reduction must be supplied as a
        reviewed artifact before reducing them.
        """

        evidence = self.security_evidence
        lifetime_target = (
            evidence.lifetime_target_bits
            if _is_int(evidence.lifetime_target_bits)
            else None
        )
        per_query_targets = (
            self.max_registrations_per_client_lifetime
            * self.max_queries_per_registration
        )
        per_registration_targets = self.max_registrations_per_client_lifetime

        def entry(
            primitive: str, estimate: float | None, target_count: int
        ) -> ComputationalSecurityLedgerEntry:
            margin = _ceil_log2_positive(target_count)
            return ComputationalSecurityLedgerEntry(
                primitive=primitive,
                single_instance_estimate_bits=(
                    estimate if _is_security_score(estimate) else None
                ),
                lifetime_target_bits=lifetime_target,
                lifetime_target_count=target_count,
                multi_target_margin_bits=margin,
                required_single_instance_bits_for_lifetime=(
                    None
                    if lifetime_target is None
                    else lifetime_target + margin
                ),
            )

        return (
            entry(
                "query_lwe",
                evidence.query_lwe_single_instance_bits,
                per_query_targets,
            ),
            entry(
                "registration_lhe",
                evidence.registration_lhe_single_instance_bits,
                per_registration_targets,
            ),
            entry(
                "hint_fhe_rlwe",
                evidence.hint_fhe_rlwe_single_instance_bits,
                per_query_targets,
            ),
            entry(
                "sis_general_bound",
                evidence.sis_general_bound_single_instance_bits,
                per_query_targets,
            ),
        )

    @property
    def matrix_seed(self) -> bytes:
        if not isinstance(self.public_matrix_seed_hex, str) or len(self.public_matrix_seed_hex) != 64:
            raise ValueError("public matrix seed must be exactly 256-bit hexadecimal")
        try:
            seed = bytes.fromhex(self.public_matrix_seed_hex)
        except ValueError as exc:
            raise ValueError("public_matrix_seed_hex is not hexadecimal") from exc
        return seed

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def digest_hex(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "name": self.name,
            "profile_kind": self.profile_kind,
            "protocol_variant": self.protocol_variant,
            "plaintext_modulus": self.p,
            "ciphertext_modulus": self.q,
            "database_rows": self.ell,
            "database_columns": self.m,
            "lwe_dimension": self.n,
            "statistical_security_bits": self.kappa,
            "proof_norm_bound": self.proof_norm_bound,
            "error_sigma": self.error_sigma,
            "query_secret_distribution": self.query_secret_distribution,
            "query_error_distribution": self.query_error_distribution,
            "registration_lhe": self.registration_lhe.to_dict(),
            "hint_fhe": self.hint_fhe.to_dict(),
            "correctness_delta": self.correctness_delta,
            "max_queries_per_registration": self.max_queries_per_registration,
            "max_registrations_per_client_lifetime": self.max_registrations_per_client_lifetime,
            "correctness_budget_bits": self.correctness_budget_bits,
            "statistical_failure_budget_bits": self.statistical_failure_budget_bits,
            "public_matrix_seed_hex": self.public_matrix_seed_hex,
            "security_evidence": self.security_evidence.__dict__,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProtocolParameters":
        allowed = {
            "schema",
            "name",
            "profile_kind",
            "protocol_variant",
            "plaintext_modulus",
            "ciphertext_modulus",
            "database_rows",
            "database_columns",
            "lwe_dimension",
            "statistical_security_bits",
            "proof_norm_bound",
            "error_sigma",
            "query_secret_distribution",
            "query_error_distribution",
            "registration_lhe",
            "hint_fhe",
            "correctness_delta",
            "max_queries_per_registration",
            "max_registrations_per_client_lifetime",
            "correctness_budget_bits",
            "statistical_failure_budget_bits",
            "public_matrix_seed_hex",
            "security_evidence",
        }
        if not isinstance(value, dict) or set(value) - allowed:
            raise ValueError("parameter profile has unexpected fields")
        data = dict(value)
        data["security_evidence"] = SecurityEvidence.from_mapping(data.get("security_evidence"))
        data["registration_lhe"] = PrimitiveContextParameters.from_mapping(
            data.get("registration_lhe"), expected_role="client-registration-lhe"
        )
        data["hint_fhe"] = PrimitiveContextParameters.from_mapping(
            data.get("hint_fhe"), expected_role="hint-delegation-fhe"
        )
        profile = cls(**data)
        profile.validate_structure()
        return profile

    @classmethod
    def load(cls, path: str | Path) -> "ProtocolParameters":
        with Path(path).open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        return cls.from_dict(value)

    def validate_structure(self) -> None:
        if self.schema != PROFILE_SCHEMA:
            raise ValueError("unsupported parameter profile schema")
        if self.profile_kind not in {"reference-only", "production-candidate"}:
            raise ValueError("profile_kind must be reference-only or production-candidate")
        if self.protocol_variant not in {
            "figure5-combined",
            "experimental-split-qlp-reference",
        }:
            raise ValueError("unsupported protocol_variant")
        if not isinstance(self.name, str) or not self.name or len(self.name.encode("utf-8")) > 128:
            raise ValueError("profile name must be non-empty and at most 128 UTF-8 bytes")
        integers = (
            self.p,
            self.q,
            self.ell,
            self.m,
            self.n,
            self.kappa,
            self.proof_norm_bound,
            self.max_queries_per_registration,
            self.max_registrations_per_client_lifetime,
            self.correctness_budget_bits,
            self.statistical_failure_budget_bits,
        )
        if any(not _is_int(value) or value <= 0 for value in integers):
            raise ValueError("integer parameters must be positive non-boolean integers")
        if self.p < 2 or self.q <= self.p:
            raise ValueError("require 2 <= p < q")
        if self.q >= 2**64:
            raise ValueError("parameter schema v2 supports q below 2^64")
        if self.kappa < 1:
            raise ValueError("statistical security parameter must be positive")
        if not math.isfinite(self.error_sigma) or self.error_sigma <= 0:
            raise ValueError("error_sigma must be a positive finite value")
        if not isinstance(self.query_secret_distribution, str) or not self.query_secret_distribution:
            raise ValueError("query secret distribution must be named")
        if not isinstance(self.query_error_distribution, str) or not self.query_error_distribution:
            raise ValueError("query error distribution must be named")
        self.registration_lhe.validate(expected_role="client-registration-lhe")
        self.hint_fhe.validate(expected_role="hint-delegation-fhe")
        if not math.isfinite(self.correctness_delta) or not 0 < self.correctness_delta < 1:
            raise ValueError("correctness_delta must lie in (0,1)")
        if self.proof_norm_bound < self.ell * self.p:
            raise ValueError("project convention requires B >= ell*p")
        _ = self.matrix_seed

    def audit(self) -> ParameterAudit:
        self.validate_structure()
        evidence = self.security_evidence
        target = evidence.lifetime_target_bits
        computational_ledger = self.computational_security_ledger
        computational_by_primitive = {
            entry.primitive: entry for entry in computational_ledger
        }

        def meets_lifetime_requirement(primitive: str) -> bool:
            entry = computational_by_primitive[primitive]
            return (
                entry.required_single_instance_bits_for_lifetime is not None
                and _is_security_score(entry.single_instance_estimate_bits)
                and entry.single_instance_estimate_bits
                >= entry.required_single_instance_bits_for_lifetime
            )

        def lifetime_requirement_detail(primitive: str, label: str) -> str:
            entry = computational_by_primitive[primitive]
            return (
                f"attach a {label} single-instance estimate of at least "
                f"{entry.required_single_instance_bits_for_lifetime} bits: "
                f"lifetime target {entry.lifetime_target_bits} + "
                f"ceil(log2({entry.lifetime_target_count}))="
                f"{entry.multi_target_margin_bits} multi-target bits"
            )

        checks = [
            AuditCheck("q-is-prime", _is_probable_prime_64(self.q), True, "q must be prime for proof compression over Z_q"),
            AuditCheck(
                "general-sis-bound-selected",
                self.general_sis_beta == (2 * self.ell + 1) * self.proof_norm_bound,
                True,
                "use beta=(2*ell+1)B; the honest-H shortcut is forbidden in this profile",
            ),
            AuditCheck(
                "nontrivial-general-sis-bound",
                self.q > self.general_sis_beta,
                True,
                f"q={self.q} must exceed beta_general={self.general_sis_beta} to exclude the trivial q*e_j SIS vector",
            ),
            AuditCheck(
                "query-error-correctness-proxy",
                self.q >= self.correctness_required_q,
                True,
                f"q={self.q} must be at least {self.correctness_required_q} under the configured subgaussian tail proxy",
            ),
            AuditCheck(
                "cumulative-correctness-budget",
                self.max_registrations_per_client_lifetime
                * self.max_queries_per_registration
                * self.correctness_delta
                <= 2 ** (-self.correctness_budget_bits),
                True,
                "max_registrations*max_queries*delta must fit the configured union-bound correctness budget",
            ),
            AuditCheck(
                "provisional-cumulative-statistical-budget",
                self.max_registrations_per_client_lifetime
                * self.max_queries_per_registration
                * self.provisional_statistical_failure_per_query
                <= 2 ** (-self.statistical_failure_budget_bits),
                True,
                "the provisional registrations*Q*(2^(-kappa+2)+q^(-gamma)) proxy must fit its budget; this is necessary but not a complete soundness proof",
            ),
            AuditCheck(
                "production-kind",
                self.profile_kind == "production-candidate",
                True,
                "reference-only profiles cannot support a production security claim",
            ),
            AuditCheck(
                "production-protocol-variant",
                self.protocol_variant == "figure5-combined",
                True,
                "only the combined Figure-5 variant can use the current production security ledger",
            ),
            AuditCheck(
                "lifetime-target-security",
                _is_int(target) and target >= 128,
                True,
                "record a client-lifetime target security level of at least 128 bits",
            ),
            AuditCheck(
                "query-lwe-single-instance-estimate",
                meets_lifetime_requirement("query_lwe"),
                True,
                lifetime_requirement_detail(
                    "query_lwe", "query-LWE"
                ),
            ),
            AuditCheck(
                "registration-lhe-single-instance-estimate",
                meets_lifetime_requirement("registration_lhe"),
                True,
                lifetime_requirement_detail(
                    "registration_lhe", "client-registration LHE"
                ),
            ),
            AuditCheck(
                "hint-fhe-rlwe-single-instance-estimate",
                meets_lifetime_requirement("hint_fhe_rlwe"),
                True,
                lifetime_requirement_detail(
                    "hint_fhe_rlwe", "hint-delegation BFV/RLWE"
                ),
            ),
            AuditCheck(
                "sis-general-single-instance-estimate",
                meets_lifetime_requirement("sis_general_bound"),
                True,
                lifetime_requirement_detail(
                    "sis_general_bound",
                    "general-bound SIS beta=(2*ell+1)B",
                ),
            ),
            AuditCheck(
                "reproducible-estimator-commit",
                isinstance(evidence.estimator_commit, str) and len(evidence.estimator_commit) >= 7,
                True,
                "pin the estimator revision used for all security estimates",
            ),
            AuditCheck(
                "estimator-artifact-digest",
                isinstance(evidence.artifact_sha256, str)
                and len(evidence.artifact_sha256) == 64
                and all(character in "0123456789abcdef" for character in evidence.artifact_sha256.lower()),
                True,
                "store the SHA-256 digest of the complete estimator output artifact",
            ),
            AuditCheck(
                "registration-context-selected",
                self.registration_lhe.complete_and_selected,
                True,
                "select and fully specify the independent client-registration LHE context",
            ),
            AuditCheck(
                "registration-plaintext-capacity",
                self.registration_lhe.plaintext_modulus is not None
                and self.registration_lhe.plaintext_modulus
                > self.ell * (self.p - 1),
                True,
                "the registration LHE plaintext modulus must exceed ell*(p-1), so canonical Z=C*D does not wrap",
            ),
            AuditCheck(
                "hint-context-selected",
                self.hint_fhe.complete_and_selected,
                True,
                "select and fully specify the independent Hs-delegation BFV/RLWE context",
            ),
            AuditCheck(
                "query-distributions-selected",
                "unvalidated" not in self.query_secret_distribution.lower()
                and "unvalidated" not in self.query_error_distribution.lower(),
                True,
                "bind the query LWE secret and error samplers to reviewed distribution identifiers",
            ),
            AuditCheck(
                "hint-plaintext-matches-q",
                self.hint_fhe.plaintext_modulus == self.q,
                True,
                "the selected Hs-delegation context must represent arithmetic modulo the query q",
            ),
            AuditCheck(
                "query-error-tail-bound-certified",
                isinstance(evidence.query_error_tail_bound_id, str)
                and len(evidence.query_error_tail_bound_id) >= 8
                and isinstance(evidence.query_error_tail_artifact_sha256, str)
                and len(evidence.query_error_tail_artifact_sha256) == 64
                and all(
                    character in "0123456789abcdef"
                    for character in evidence.query_error_tail_artifact_sha256.lower()
                ),
                True,
                "bind the named query error sampler to a reviewed tail-bound formula and artifact; the generic subgaussian proxy alone is insufficient",
            ),
            AuditCheck(
                "leaky-secret-feedback-accounted",
                computational_by_primitive[
                    "query_lwe"
                ].required_single_instance_bits_for_lifetime
                is not None
                and _is_security_score(evidence.query_secret_min_entropy_bits)
                and _is_int(evidence.query_feedback_leakage_bits)
                and evidence.query_feedback_leakage_bits == 1
                and evidence.query_secret_min_entropy_bits
                >= computational_by_primitive[
                    "query_lwe"
                ].required_single_instance_bits_for_lifetime
                + evidence.query_feedback_leakage_bits
                and isinstance(evidence.leaky_secret_argument_id, str)
                and len(evidence.leaky_secret_argument_id) >= 8
                and isinstance(evidence.leaky_secret_artifact_sha256, str)
                and len(evidence.leaky_secret_artifact_sha256) == 64
                and all(
                    character in "0123456789abcdef"
                    for character in evidence.leaky_secret_artifact_sha256.lower()
                ),
                True,
                "account for the at-most-one-bit combined Figure-5 final feedback after the query-LWE lifetime multi-target margin, using fresh s, sampler min-entropy and a reviewed leaky-secret LWE argument; split QLP needs a separate ledger",
            ),
            AuditCheck(
                "honest-public-matrix-seed-source",
                isinstance(evidence.public_matrix_seed_source, str)
                and len(evidence.public_matrix_seed_source) >= 8,
                True,
                "record a client-controlled or publicly verifiable random source for A; the malicious database server must not choose it",
            ),
            AuditCheck(
                "setup-transcript-digest",
                isinstance(evidence.setup_transcript_sha256, str)
                and len(evidence.setup_transcript_sha256) == 64
                and all(
                    character in "0123456789abcdef"
                    for character in evidence.setup_transcript_sha256.lower()
                ),
                True,
                "store the SHA-256 digest of the public-parameter generation transcript",
            ),
            AuditCheck(
                "audited-native-backend-integrated",
                False,
                True,
                "the current implementation has no audited native backend; this hard blocker cannot be satisfied by editing JSON evidence",
            ),
        ]
        return ParameterAudit(
            profile_name=self.name,
            protocol_variant=self.protocol_variant,
            max_queries_per_registration=self.max_queries_per_registration,
            max_registrations_per_client_lifetime=self.max_registrations_per_client_lifetime,
            general_sis_beta=self.general_sis_beta,
            honest_hint_beta_for_comparison=self.honest_hint_beta_for_comparison,
            correctness_required_q=self.correctness_required_q,
            cumulative_correctness_failure_bound=(
                self.max_registrations_per_client_lifetime
                * self.max_queries_per_registration
                * self.correctness_delta
            ),
            cumulative_statistical_failure_bound=(
                self.max_registrations_per_client_lifetime
                * self.max_queries_per_registration
                * self.provisional_statistical_failure_per_query
            ),
            compression_rows=self.gamma,
            lifetime_target_bits=(target if _is_int(target) else None),
            computational_security_ledger=computational_ledger,
            checks=tuple(checks),
        )

    def require_production_ready(self) -> None:
        audit = self.audit()
        if not audit.production_ready:
            raise ValueError("parameter profile is not production-ready: " + "; ".join(audit.blockers))

    def require_executable_math(self) -> None:
        """Reject profiles that violate non-negotiable protocol equations."""

        self.validate_structure()
        failures = []
        if not _is_probable_prime_64(self.q):
            failures.append("q is not prime")
        if self.q <= self.general_sis_beta:
            failures.append("q does not exceed the general SIS bound")
        if self.q < self.correctness_required_q:
            failures.append("q does not satisfy the configured subgaussian correctness proxy")
        if (
            self.max_registrations_per_client_lifetime
            * self.max_queries_per_registration
            * self.correctness_delta
            > 2 ** (-self.correctness_budget_bits)
        ):
            failures.append("the cumulative correctness budget is exceeded")
        if (
            self.registration_lhe.plaintext_modulus is None
            or self.registration_lhe.plaintext_modulus <= self.ell * (self.p - 1)
        ):
            failures.append("the registration LHE plaintext modulus cannot represent honest Z without wraparound")
        if self.hint_fhe.plaintext_modulus != self.q:
            failures.append("the Hs-delegation plaintext modulus must equal q")
        if (
            self.max_registrations_per_client_lifetime
            * self.max_queries_per_registration
            * self.provisional_statistical_failure_per_query
            > 2 ** (-self.statistical_failure_budget_bits)
        ):
            failures.append("the provisional cumulative statistical budget is exceeded")
        if failures:
            raise ValueError("parameter profile cannot execute: " + "; ".join(failures))


def reference_parameters(
    *,
    rows: int = 4,
    columns: int = 8,
    lwe_dimension: int = 4,
    statistical_security_bits: int = 16,
    protocol_variant: str = "figure5-combined",
) -> ProtocolParameters:
    """Return a fast, explicitly insecure profile for control-flow tests."""

    proof_bound = rows * 16
    provisional_required_q = math.ceil(
        16 * 1.0 * (2 * proof_bound) * math.sqrt(2 * columns * math.log(2 / 2**-20))
    )
    provisional_general_beta = (2 * rows + 1) * proof_bound
    minimum_q = max(provisional_required_q, provisional_general_beta + 1)
    ciphertext_modulus = 65537 if minimum_q <= 65537 else 2305843009213693951
    if minimum_q > ciphertext_modulus:
        raise ValueError("reference dimensions exceed the bundled toy moduli")
    compression_rows = math.ceil(statistical_security_bits / math.log2(ciphertext_modulus))
    statistical_proxy = 64 * (
        2 ** (-statistical_security_bits + 2)
        + ciphertext_modulus ** (-compression_rows)
    )
    statistical_budget_bits = max(1, math.floor(-math.log2(statistical_proxy)))
    profile = ProtocolParameters(
        name=f"reference-{rows}x{columns}",
        profile_kind="reference-only",
        protocol_variant=protocol_variant,
        plaintext_modulus=16,
        ciphertext_modulus=ciphertext_modulus,
        database_rows=rows,
        database_columns=columns,
        lwe_dimension=lwe_dimension,
        statistical_security_bits=statistical_security_bits,
        proof_norm_bound=proof_bound,
        # Hoeffding gives the bounded uniform-ternary error a conservative
        # subgaussian parameter of 1.0.  This is a test profile, not an LWE
        # security parameter selection.
        error_sigma=1.0,
        query_secret_distribution="uniform-ternary-reference",
        query_error_distribution="uniform-ternary-reference",
        registration_lhe=PrimitiveContextParameters(
            role="client-registration-lhe",
            scheme="transparent-reference-matmul",
            status="reference-only",
            dimension=1,
            plaintext_modulus=16 * rows,
            ciphertext_moduli_bits=(ciphertext_modulus.bit_length(),),
            secret_distribution="plaintext-reference",
            error_distribution="none",
            error_parameter=0.0,
        ),
        hint_fhe=PrimitiveContextParameters(
            role="hint-delegation-fhe",
            scheme="transparent-reference-matmul",
            status="reference-only",
            dimension=1,
            plaintext_modulus=ciphertext_modulus,
            ciphertext_moduli_bits=(ciphertext_modulus.bit_length(),),
            secret_distribution="plaintext-reference",
            error_distribution="none",
            error_parameter=0.0,
        ),
        correctness_delta=2**-20,
        max_queries_per_registration=64,
        max_registrations_per_client_lifetime=1,
        correctness_budget_bits=10,
        statistical_failure_budget_bits=statistical_budget_bits,
        public_matrix_seed_hex="5a" * 32,
    )
    profile.validate_structure()
    return profile
