// Copyright 2026
// Licensed under the Apache License, Version 2.0.

#include "lwe/negacyclic_ntt.h"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "shell_encryption/status_macros.h"

namespace hintless_pir {
namespace lwe {

absl::StatusOr<std::unique_ptr<NegacyclicNtt>> NegacyclicNtt::Create(
    uint64_t modulus, int log_degree) {
  if (log_degree <= 0 || log_degree >= 31) {
    return absl::InvalidArgumentError("`log_degree` must be in [1, 30].");
  }
  const uint64_t two_degree = uint64_t{1} << (log_degree + 1);
  if (modulus % two_degree != 1) {
    return absl::InvalidArgumentError(absl::StrCat(
        "NTT modulus must equal 1 mod 2N; modulus=", modulus,
        ", degree=", uint64_t{1} << log_degree));
  }
  RLWE_ASSIGN_OR_RETURN(auto modulus_params,
                        ModularInt::Params::Create(modulus));
  RLWE_ASSIGN_OR_RETURN(
      auto ntt_params,
      rlwe::InitializeNttParameters<ModularInt>(log_degree,
                                                modulus_params.get()));
  return std::unique_ptr<NegacyclicNtt>(new NegacyclicNtt(
      modulus, log_degree, std::move(modulus_params), std::move(ntt_params)));
}

absl::StatusOr<NegacyclicNtt::Polynomial> NegacyclicNtt::Forward(
    absl::Span<const uint32_t> coefficients) const {
  if (coefficients.size() != degree()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "coefficient count must equal ring degree: got ",
        coefficients.size(), ", want ", degree()));
  }
  std::vector<ModularInt> imported;
  imported.reserve(coefficients.size());
  for (uint32_t coefficient : coefficients) {
    if (coefficient >= modulus_) {
      return absl::InvalidArgumentError(
          "coefficient is not in canonical Z_q representation");
    }
    RLWE_ASSIGN_OR_RETURN(
        auto value, ModularInt::ImportInt(coefficient, modulus_params_.get()));
    imported.push_back(value);
  }
  Polynomial result = Polynomial::ConvertToNtt(
      std::move(imported), &ntt_params_, modulus_params_.get());
  if (!result.IsValid()) {
    return absl::InternalError("forward negacyclic NTT failed");
  }
  return result;
}

absl::StatusOr<std::vector<uint32_t>> NegacyclicNtt::Inverse(
    const Polynomial& polynomial) const {
  if (modulus_ > UINT32_MAX) {
    return absl::FailedPreconditionError(
        "32-bit inverse requested for a modulus larger than uint32_t");
  }
  if (!polynomial.IsValid() || polynomial.Len() != degree()) {
    return absl::InvalidArgumentError(
        "NTT polynomial has the wrong degree");
  }
  std::vector<ModularInt> imported =
      polynomial.InverseNtt(&ntt_params_, modulus_params_.get());
  if (imported.size() != degree()) {
    return absl::InternalError("inverse negacyclic NTT failed");
  }
  std::vector<uint32_t> result;
  result.reserve(imported.size());
  for (const ModularInt& coefficient : imported) {
    result.push_back(
        static_cast<uint32_t>(coefficient.ExportInt(modulus_params_.get())));
  }
  return result;
}

absl::StatusOr<NegacyclicNtt::Polynomial> NegacyclicNtt::Forward64(
    absl::Span<const uint64_t> coefficients) const {
  if (coefficients.size() != degree()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "coefficient count must equal ring degree: got ",
        coefficients.size(), ", want ", degree()));
  }
  std::vector<ModularInt> imported;
  imported.reserve(coefficients.size());
  for (uint64_t coefficient : coefficients) {
    if (coefficient >= modulus_) {
      return absl::InvalidArgumentError(
          "coefficient is not in canonical Z_q representation");
    }
    RLWE_ASSIGN_OR_RETURN(
        auto value, ModularInt::ImportInt(coefficient, modulus_params_.get()));
    imported.push_back(value);
  }
  Polynomial result = Polynomial::ConvertToNtt(
      std::move(imported), &ntt_params_, modulus_params_.get());
  if (!result.IsValid()) {
    return absl::InternalError("forward negacyclic NTT failed");
  }
  return result;
}

absl::StatusOr<std::vector<uint64_t>> NegacyclicNtt::Inverse64(
    const Polynomial& polynomial) const {
  if (!polynomial.IsValid() || polynomial.Len() != degree()) {
    return absl::InvalidArgumentError(
        "NTT polynomial has the wrong degree");
  }
  std::vector<ModularInt> imported =
      polynomial.InverseNtt(&ntt_params_, modulus_params_.get());
  if (imported.size() != degree()) {
    return absl::InternalError("inverse negacyclic NTT failed");
  }
  std::vector<uint64_t> result;
  result.reserve(imported.size());
  for (const ModularInt& coefficient : imported) {
    result.push_back(coefficient.ExportInt(modulus_params_.get()));
  }
  return result;
}

absl::StatusOr<std::vector<uint32_t>> NegacyclicNtt::Multiply(
    absl::Span<const uint32_t> lhs,
    absl::Span<const uint32_t> rhs) const {
  RLWE_ASSIGN_OR_RETURN(Polynomial lhs_ntt, Forward(lhs));
  RLWE_ASSIGN_OR_RETURN(Polynomial rhs_ntt, Forward(rhs));
  RLWE_RETURN_IF_ERROR(lhs_ntt.MulInPlace(rhs_ntt, modulus_params_.get()));
  return Inverse(lhs_ntt);
}

absl::StatusOr<std::vector<uint64_t>> NegacyclicNtt::Multiply64(
    absl::Span<const uint64_t> lhs,
    absl::Span<const uint64_t> rhs) const {
  RLWE_ASSIGN_OR_RETURN(Polynomial lhs_ntt, Forward64(lhs));
  RLWE_ASSIGN_OR_RETURN(Polynomial rhs_ntt, Forward64(rhs));
  RLWE_RETURN_IF_ERROR(lhs_ntt.MulInPlace(rhs_ntt, modulus_params_.get()));
  return Inverse64(lhs_ntt);
}

NegacyclicNtt::Polynomial NegacyclicNtt::ZeroNtt() const {
  return Polynomial(degree(), modulus_params_.get());
}

absl::Status NegacyclicNtt::MultiplyInPlace(Polynomial& lhs,
                                             const Polynomial& rhs) const {
  if (!lhs.IsValid() || !rhs.IsValid() || lhs.Len() != degree() ||
      rhs.Len() != degree()) {
    return absl::InvalidArgumentError("NTT polynomial has the wrong degree");
  }
  return lhs.MulInPlace(rhs, modulus_params_.get());
}

absl::Status NegacyclicNtt::FusedMultiplyAddInPlace(
    Polynomial& accumulator, const Polynomial& lhs,
    const Polynomial& rhs) const {
  if (!accumulator.IsValid() || !lhs.IsValid() || !rhs.IsValid() ||
      accumulator.Len() != degree() || lhs.Len() != degree() ||
      rhs.Len() != degree()) {
    return absl::InvalidArgumentError("NTT polynomial has the wrong degree");
  }
  return accumulator.FusedMulAddInPlace(lhs, rhs, modulus_params_.get());
}

}  // namespace lwe
}  // namespace hintless_pir
