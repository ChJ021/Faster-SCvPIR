// Copyright 2026
// Licensed under the Apache License, Version 2.0.

#ifndef HINTLESS_PIR_HINTLESS_SIMPLEPIR_MAIN_PREPROCESSOR_H_
#define HINTLESS_PIR_HINTLESS_SIMPLEPIR_MAIN_PREPROCESSOR_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "hintless_simplepir/database_hwy.h"
#include "hintless_simplepir/parameters.h"
#include "lwe/matrix_conversion.h"
#include "lwe/negacyclic_ntt.h"
#include "lwe/types.h"

namespace hintless_pir {
namespace hintless_simplepir {

inline constexpr char kYpirMainPadDomain[] =
    "small-client-pir/main-pad/ypir-ntt/v1";
inline constexpr int kYpirStructuredPadVersion = 1;

struct MainPreprocessorMetadata {
  MainPreprocessorBackend backend;
  std::string backend_name;
  int ring_degree;
  int pad_block_count;
  int structured_pad_version;
  uint64_t modulus;
  int secret_dimension;
  std::string prg_domain;
  std::string security_status;
};

// Returns the metadata implied by `params` without expanding or retaining the
// public pad. Clients use this to validate the server's public parameters while
// keeping the pad backend ephemeral.
absl::StatusOr<MainPreprocessorMetadata> DescribeMainPreprocessor(
    const Parameters& params);

// Uniform interface consumed by the server, client and verifier for the main
// SimplePIR public pad.  Implementations must return canonical coefficients in
// Z_q and retain the existing row-major H/As/ZA layouts.
class MainPreprocessor {
 public:
  virtual ~MainPreprocessor() = default;

  virtual absl::StatusOr<std::vector<Database::LweMatrix>> ComputeHint(
      const Database& database) const = 0;
  virtual absl::StatusOr<lwe::Vector> ComputePadTimesSecret(
      const lwe::Vector& secret) const = 0;
  virtual absl::StatusOr<VMatrix> MultiplyRightByPad(
      const VMatrix& left) const = 0;
  virtual MainPreprocessorMetadata Metadata() const = 0;

  // Non-null only for the legacy dense backend.  This preserves the existing
  // diagnostic accessor without forcing the YPIR backend to allocate A.
  virtual const lwe::Matrix* DensePadIfMaterialized() const = 0;

  // This method is intentionally test/debug-only.  Production YPIR paths do
  // not materialize the db_cols x secret_dimension public matrix.
  virtual absl::StatusOr<lwe::Matrix> MaterializePadForTesting() const = 0;
};

absl::StatusOr<std::unique_ptr<MainPreprocessor>> CreateMainPreprocessor(
    const Parameters& params, absl::string_view public_seed);

}  // namespace hintless_simplepir
}  // namespace hintless_pir

#endif  // HINTLESS_PIR_HINTLESS_SIMPLEPIR_MAIN_PREPROCESSOR_H_
