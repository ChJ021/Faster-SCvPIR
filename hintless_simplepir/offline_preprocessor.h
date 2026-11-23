// Copyright 2026
// Licensed under the Apache License, Version 2.0.

#ifndef HINTLESS_PIR_HINTLESS_SIMPLEPIR_OFFLINE_PREPROCESSOR_H_
#define HINTLESS_PIR_HINTLESS_SIMPLEPIR_OFFLINE_PREPROCESSOR_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "hintless_simplepir/database_hwy.h"
#include "hintless_simplepir/parameters.h"
#include "lwe/negacyclic_ntt.h"
#include "verisimplepir/src/lib/pir/lhe.h"

namespace hintless_pir {
namespace hintless_simplepir {

inline constexpr char kYpirOfflinePadDomain[] =
    "small-client-pir/offline-pad/ypir-ntt/v1";
inline constexpr int kYpirOfflineStructuredPadVersion = 1;

struct OfflinePreprocessorMetadata {
  OfflinePreprocessorBackend backend;
  std::string backend_name;
  int ring_degree;
  int pad_block_count;
  int structured_pad_version;
  uint64_t modulus;
  int secret_dimension;
  std::string prg_domain;
  std::string security_status;
};

// Exact structured public pad for the offline verification LWE instance.
// Production methods never materialize the db_rows x ring_degree matrix A_2.
class YpirOfflinePreprocessor {
 public:
  static absl::StatusOr<std::unique_ptr<YpirOfflinePreprocessor>> Create(
      const Parameters& params, absl::string_view public_seed);

  // Computes H_2 = D^T A_2.  The result layout is
  // shard, database column, secret coefficient.
  absl::StatusOr<std::vector<Database::LweMatrix64>> ComputeHint(
      const Database& database) const;

  // Computes A_2 s as a db_rows x 1 column vector.
  absl::StatusOr<Matrix64> ComputePadTimesSecret(
      const Matrix64& secret) const;

  // Encrypts every row of C using the same structured A_2 used by ComputeHint.
  absl::StatusOr<
      std::pair<std::vector<Matrix64>, std::vector<Matrix64>>>
  EncryptChallenges(const LHE& lhe, const BinaryMatrix& plaintexts) const;

  OfflinePreprocessorMetadata Metadata() const;

  // Test/debug-only dense expansion.  Production paths must not call this.
  absl::StatusOr<Matrix64> MaterializePadForTesting() const;

 private:
  YpirOfflinePreprocessor(
      Parameters params, std::unique_ptr<lwe::NegacyclicNtt> ntt,
      std::vector<std::vector<uint64_t>> blocks,
      std::vector<lwe::NegacyclicNtt::Polynomial> blocks_ntt,
      std::vector<lwe::NegacyclicNtt::Polynomial> transpose_blocks_ntt)
      : params_(std::move(params)),
        ntt_(std::move(ntt)),
        blocks_(std::move(blocks)),
        blocks_ntt_(std::move(blocks_ntt)),
        transpose_blocks_ntt_(std::move(transpose_blocks_ntt)) {}

  const Parameters params_;
  const std::unique_ptr<lwe::NegacyclicNtt> ntt_;
  const std::vector<std::vector<uint64_t>> blocks_;
  const std::vector<lwe::NegacyclicNtt::Polynomial> blocks_ntt_;
  const std::vector<lwe::NegacyclicNtt::Polynomial> transpose_blocks_ntt_;
};

}  // namespace hintless_simplepir
}  // namespace hintless_pir

#endif  // HINTLESS_PIR_HINTLESS_SIMPLEPIR_OFFLINE_PREPROCESSOR_H_
