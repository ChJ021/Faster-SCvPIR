// Copyright 2026
// Licensed under the Apache License, Version 2.0.

#ifndef HINTLESS_PIR_LWE_NEGACYCLIC_NTT_H_
#define HINTLESS_PIR_LWE_NEGACYCLIC_NTT_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/types/span.h"
#include "shell_encryption/montgomery.h"
#include "shell_encryption/ntt_parameters.h"
#include "shell_encryption/polynomial.h"

namespace hintless_pir {
namespace lwe {

// A small checked wrapper around SHELL's exact NTT implementation.  All
// products are in Z_q[X]/(X^degree + 1); no modulus switching, rounding, or
// coefficient truncation is performed.
class NegacyclicNtt {
 public:
  using ModularInt = rlwe::MontgomeryInt<uint64_t>;
  using Polynomial = rlwe::Polynomial<ModularInt>;

  static absl::StatusOr<std::unique_ptr<NegacyclicNtt>> Create(
      uint64_t modulus, int log_degree);

  int degree() const { return 1 << log_degree_; }
  int log_degree() const { return log_degree_; }
  uint64_t modulus() const { return modulus_; }

  absl::StatusOr<Polynomial> Forward(
      absl::Span<const uint32_t> coefficients) const;
  absl::StatusOr<std::vector<uint32_t>> Inverse(
      const Polynomial& polynomial) const;
  absl::StatusOr<std::vector<uint32_t>> Multiply(
      absl::Span<const uint32_t> lhs,
      absl::Span<const uint32_t> rhs) const;

  // 64-bit coefficient variants for exact arithmetic under the offline
  // verification modulus.  These use the same Montgomery/NTT representation
  // as the 32-bit methods and never round or switch moduli.
  absl::StatusOr<Polynomial> Forward64(
      absl::Span<const uint64_t> coefficients) const;
  absl::StatusOr<std::vector<uint64_t>> Inverse64(
      const Polynomial& polynomial) const;
  absl::StatusOr<std::vector<uint64_t>> Multiply64(
      absl::Span<const uint64_t> lhs,
      absl::Span<const uint64_t> rhs) const;

  Polynomial ZeroNtt() const;
  absl::Status MultiplyInPlace(Polynomial& lhs,
                               const Polynomial& rhs) const;
  absl::Status FusedMultiplyAddInPlace(Polynomial& accumulator,
                                       const Polynomial& lhs,
                                       const Polynomial& rhs) const;

 private:
  NegacyclicNtt(
      uint64_t modulus, int log_degree,
      std::unique_ptr<const ModularInt::Params> modulus_params,
      rlwe::NttParameters<ModularInt> ntt_params)
      : modulus_(modulus),
        log_degree_(log_degree),
        modulus_params_(std::move(modulus_params)),
        ntt_params_(std::move(ntt_params)) {}

  uint64_t modulus_;
  int log_degree_;
  std::unique_ptr<const ModularInt::Params> modulus_params_;
  rlwe::NttParameters<ModularInt> ntt_params_;
};

}  // namespace lwe
}  // namespace hintless_pir

#endif  // HINTLESS_PIR_LWE_NEGACYCLIC_NTT_H_
