// Copyright 2026
// Licensed under the Apache License, Version 2.0.

#include "hintless_simplepir/main_preprocessor.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <openssl/sha.h>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "hintless_simplepir/database_hwy.h"
#include "hintless_simplepir/parameters.h"
#include "lwe/lwe_symmetric_encryption.h"
#include "lwe/matrix_conversion.h"
#include "lwe/negacyclic_ntt.h"
#include "lwe/types.h"
#include "shell_encryption/prng/prng.h"
#include "shell_encryption/prng/single_thread_chacha_prng.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/status_macros.h"

namespace hintless_pir {
namespace hintless_simplepir {
namespace {

constexpr uint64_t kMainModulus = SOL_NTT_PRIME;

MainPreprocessorMetadata DenseMetadata(const Parameters& params) {
  return MainPreprocessorMetadata{
      .backend = MainPreprocessorBackend::kDenseLwe,
      .backend_name = "dense-lwe",
      .ring_degree = 0,
      .pad_block_count = 0,
      .structured_pad_version = 0,
      .modulus = kMainModulus,
      .secret_dimension = params.lwe_secret_dim,
      .prg_domain = "small-client-pir/main-pad/dense-lwe/legacy",
      .security_status = "baseline-lwe",
  };
}

MainPreprocessorMetadata YpirMetadata(const Parameters& params) {
  return MainPreprocessorMetadata{
      .backend = MainPreprocessorBackend::kYpirNtt,
      .backend_name = "ypir-exact-ntt",
      .ring_degree = 1 << params.main_ring_log_n,
      .pad_block_count = params.main_pad_block_count,
      .structured_pad_version = params.structured_pad_version,
      .modulus = kMainModulus,
      .secret_dimension = params.lwe_secret_dim,
      .prg_domain = kYpirMainPadDomain,
      .security_status =
          "experimental-ring-lwe-ring-sis-parameters-not-audited",
  };
}

uint32_t AddMod(uint32_t lhs, uint32_t rhs) {
  const uint64_t sum = static_cast<uint64_t>(lhs) + rhs;
  return static_cast<uint32_t>(sum >= kMainModulus ? sum - kMainModulus
                                                   : sum);
}

uint32_t MulMod(uint32_t lhs, uint32_t rhs) {
  return static_cast<uint32_t>((static_cast<uint64_t>(lhs) * rhs) %
                               kMainModulus);
}

uint32_t NegateMod(uint32_t value) {
  return value == 0 ? 0 : static_cast<uint32_t>(kMainModulus - value);
}

absl::StatusOr<std::unique_ptr<rlwe::SecurePrng>> CreatePadPrng(
    const Parameters& params, absl::string_view seed) {
  if (params.prng_type == rlwe::PRNG_TYPE_HKDF) {
    RLWE_ASSIGN_OR_RETURN(auto prng, rlwe::SingleThreadHkdfPrng::Create(seed));
    return std::unique_ptr<rlwe::SecurePrng>(std::move(prng));
  }
  if (params.prng_type == rlwe::PRNG_TYPE_CHACHA) {
    RLWE_ASSIGN_OR_RETURN(auto prng,
                          rlwe::SingleThreadChaChaPrng::Create(seed));
    return std::unique_ptr<rlwe::SecurePrng>(std::move(prng));
  }
  return absl::InvalidArgumentError("unsupported PRNG for main public pad");
}

absl::StatusOr<std::string> DeriveYpirPadSeed(
    const Parameters& params, absl::string_view public_seed) {
  size_t output_length;
  if (params.prng_type == rlwe::PRNG_TYPE_HKDF) {
    output_length = rlwe::SingleThreadHkdfPrng::SeedLength();
  } else if (params.prng_type == rlwe::PRNG_TYPE_CHACHA) {
    output_length = rlwe::SingleThreadChaChaPrng::SeedLength();
  } else {
    return absl::InvalidArgumentError("unsupported PRNG for YPIR pad seed");
  }
  if (output_length > SHA512_DIGEST_LENGTH) {
    return absl::InternalError("YPIR pad seed length exceeds SHA-512 output");
  }
  std::string input;
  input.reserve(sizeof(kYpirMainPadDomain) + public_seed.size());
  input.append(kYpirMainPadDomain);
  input.push_back('\0');
  input.append(public_seed.data(), public_seed.size());
  std::array<unsigned char, SHA512_DIGEST_LENGTH> digest{};
  SHA512(reinterpret_cast<const unsigned char*>(input.data()), input.size(),
         digest.data());
  return std::string(reinterpret_cast<const char*>(digest.data()),
                     output_length);
}

class DenseMainPreprocessor final : public MainPreprocessor {
 public:
  static absl::StatusOr<std::unique_ptr<DenseMainPreprocessor>> Create(
      const Parameters& params, absl::string_view public_seed) {
    RLWE_ASSIGN_OR_RETURN(auto prng, CreatePadPrng(params, public_seed));
    RLWE_ASSIGN_OR_RETURN(
        auto pad,
        lwe::ExpandPad<rlwe::SecurePrng>(params.db_cols,
                                        params.lwe_secret_dim, prng.get()));
    return absl::WrapUnique(
        new DenseMainPreprocessor(params, std::move(pad)));
  }

  absl::StatusOr<std::vector<Database::LweMatrix>> ComputeHint(
      const Database& database) const override {
    return database.DirectMatrixProduct(ImportLweMatrix(pad_));
  }

  absl::StatusOr<lwe::Vector> ComputePadTimesSecret(
      const lwe::Vector& secret) const override {
    if (secret.size() != params_.lwe_secret_dim) {
      return absl::InvalidArgumentError(
          "secret length does not match dense pad dimension");
    }
    lwe::Vector output = lwe::Vector::Zero(params_.db_cols);
    for (int64_t row = 0; row < params_.db_cols; ++row) {
      uint32_t accumulator = 0;
      for (int col = 0; col < params_.lwe_secret_dim; ++col) {
        accumulator = AddMod(
            accumulator,
            MulMod(pad_(row, col), secret(col) % kMainModulus));
      }
      output(row) = accumulator;
    }
    return output;
  }

  absl::StatusOr<VMatrix> MultiplyRightByPad(
      const VMatrix& left) const override {
    if (left.cols != static_cast<uint64_t>(params_.db_cols)) {
      return absl::InvalidArgumentError(
          "left matrix width does not match dense pad row count");
    }
    VMatrix output(left.rows, params_.lwe_secret_dim);
    for (uint64_t row = 0; row < left.rows; ++row) {
      for (int col = 0; col < params_.lwe_secret_dim; ++col) {
        uint32_t accumulator = 0;
        for (int64_t k = 0; k < params_.db_cols; ++k) {
          accumulator = AddMod(
              accumulator,
              MulMod(left.getElem(row, k) % kMainModulus, pad_(k, col)));
        }
        output.data[row * output.cols + col] = accumulator;
      }
    }
    return output;
  }

  MainPreprocessorMetadata Metadata() const override {
    return DenseMetadata(params_);
  }

  const lwe::Matrix* DensePadIfMaterialized() const override { return &pad_; }

  absl::StatusOr<lwe::Matrix> MaterializePadForTesting() const override {
    return pad_;
  }

 private:
  DenseMainPreprocessor(Parameters params, lwe::Matrix pad)
      : params_(std::move(params)), pad_(std::move(pad)) {}

  const Parameters params_;
  const lwe::Matrix pad_;
};

class YpirMainPreprocessor final : public MainPreprocessor {
 public:
  static absl::StatusOr<std::unique_ptr<YpirMainPreprocessor>> Create(
      const Parameters& params, absl::string_view public_seed) {
    if (params.main_ring_log_n <= 0 || params.main_ring_log_n >= 31) {
      return absl::InvalidArgumentError(
          "YPIR main ring log degree must be in [1, 30]");
    }
    const int degree = 1 << params.main_ring_log_n;
    if (params.lwe_secret_dim != degree) {
      return absl::InvalidArgumentError(absl::StrCat(
          "YPIR main requires lwe_secret_dim == ring degree; got ",
          params.lwe_secret_dim, " and ", degree));
    }
    if (params.db_cols % degree != 0) {
      return absl::InvalidArgumentError(
          "YPIR main requires db_cols to be divisible by ring degree");
    }
    const int block_count = params.db_cols / degree;
    if (params.main_pad_block_count != block_count) {
      return absl::InvalidArgumentError(absl::StrCat(
          "YPIR main pad block count mismatch: got ",
          params.main_pad_block_count, ", derived ", block_count));
    }
    if (params.structured_pad_version != kYpirStructuredPadVersion) {
      return absl::InvalidArgumentError(
          "unsupported YPIR structured pad version");
    }

    RLWE_ASSIGN_OR_RETURN(auto ntt,
                          lwe::NegacyclicNtt::Create(kMainModulus,
                                                    params.main_ring_log_n));
    RLWE_ASSIGN_OR_RETURN(const std::string domain_seed,
                          DeriveYpirPadSeed(params, public_seed));
    RLWE_ASSIGN_OR_RETURN(auto prng, CreatePadPrng(params, domain_seed));
    RLWE_ASSIGN_OR_RETURN(
        auto sampled,
        lwe::ExpandPad<rlwe::SecurePrng>(block_count, degree, prng.get()));

    std::vector<std::vector<uint32_t>> blocks(block_count,
                                               std::vector<uint32_t>(degree));
    std::vector<lwe::NegacyclicNtt::Polynomial> blocks_ntt;
    std::vector<lwe::NegacyclicNtt::Polynomial> transpose_blocks_ntt;
    blocks_ntt.reserve(block_count);
    transpose_blocks_ntt.reserve(block_count);
    for (int block = 0; block < block_count; ++block) {
      for (int i = 0; i < degree; ++i) {
        blocks[block][i] = sampled(block, i);
      }
      RLWE_ASSIGN_OR_RETURN(auto block_ntt, ntt->Forward(blocks[block]));
      blocks_ntt.push_back(std::move(block_ntt));

      // If NC(a)[i,j] = a[j-i] with negacyclic wrap, then NC(a)*s is
      // the negacyclic convolution of (a0,-aN-1,...,-a1) with s.
      std::vector<uint32_t> transposed(degree);
      transposed[0] = blocks[block][0];
      for (int i = 1; i < degree; ++i) {
        transposed[i] = NegateMod(blocks[block][degree - i]);
      }
      RLWE_ASSIGN_OR_RETURN(auto transpose_ntt, ntt->Forward(transposed));
      transpose_blocks_ntt.push_back(std::move(transpose_ntt));
    }
    return absl::WrapUnique(new YpirMainPreprocessor(
        params, std::move(ntt), std::move(blocks), std::move(blocks_ntt),
        std::move(transpose_blocks_ntt)));
  }

  absl::StatusOr<std::vector<Database::LweMatrix>> ComputeHint(
      const Database& database) const override {
    absl::Span<const Database::RawMatrix> shards = database.DataTranspose();
    if (shards.size() != database.NumShards()) {
      return absl::InternalError("database transpose shard count mismatch");
    }
    std::vector<Database::LweMatrix> output(shards.size());
    const int degree = ntt_->degree();
    const int values_per_word =
        sizeof(Database::BlockType) / sizeof(lwe::DBInteger);
    const uint32_t db_mask = params_.lwe_plaintext_bit_size == 8
                                 ? 0xffu
                                 : ((uint32_t{1}
                                     << params_.lwe_plaintext_bit_size) -
                                    1);

    for (size_t shard = 0; shard < shards.size(); ++shard) {
      if (shards[shard].size() != params_.db_rows) {
        return absl::InvalidArgumentError(
            "database transpose row count mismatch");
      }
      Database::LweMatrix& hint = output[shard];
      hint.resize(params_.db_rows);
      std::vector<uint32_t> coefficients(degree);
      for (int64_t row = 0; row < params_.db_rows; ++row) {
        if (shards[shard][row].size() * values_per_word < params_.db_cols) {
          return absl::InvalidArgumentError(
              "packed database transpose row is too short");
        }
        auto accumulator = ntt_->ZeroNtt();
        for (int block = 0; block < params_.main_pad_block_count; ++block) {
          const int64_t base_col = static_cast<int64_t>(block) * degree;
          for (int i = 0; i < degree; ++i) {
            const int64_t col = base_col + i;
            const int64_t word = col / values_per_word;
            const int shift = (col % values_per_word) * 8;
            coefficients[i] = static_cast<uint32_t>(
                (shards[shard][row][word] >> shift) & db_mask);
          }
          RLWE_ASSIGN_OR_RETURN(auto data_ntt, ntt_->Forward(coefficients));
          RLWE_RETURN_IF_ERROR(ntt_->FusedMultiplyAddInPlace(
              accumulator, data_ntt, blocks_ntt_[block]));
        }
        RLWE_ASSIGN_OR_RETURN(hint[row], ntt_->Inverse(accumulator));
      }
    }
    return output;
  }

  absl::StatusOr<lwe::Vector> ComputePadTimesSecret(
      const lwe::Vector& secret) const override {
    const int degree = ntt_->degree();
    if (secret.size() != degree) {
      return absl::InvalidArgumentError(
          "secret length does not match YPIR ring degree");
    }
    std::vector<uint32_t> secret_coefficients(degree);
    for (int i = 0; i < degree; ++i) {
      secret_coefficients[i] = secret(i) % kMainModulus;
    }
    RLWE_ASSIGN_OR_RETURN(auto secret_ntt,
                          ntt_->Forward(secret_coefficients));
    lwe::Vector output(params_.db_cols);
    for (int block = 0; block < params_.main_pad_block_count; ++block) {
      auto product = transpose_blocks_ntt_[block];
      RLWE_RETURN_IF_ERROR(ntt_->MultiplyInPlace(product, secret_ntt));
      RLWE_ASSIGN_OR_RETURN(auto coefficients, ntt_->Inverse(product));
      for (int i = 0; i < degree; ++i) {
        output(block * degree + i) = coefficients[i];
      }
    }
    return output;
  }

  absl::StatusOr<VMatrix> MultiplyRightByPad(
      const VMatrix& left) const override {
    if (left.cols != static_cast<uint64_t>(params_.db_cols)) {
      return absl::InvalidArgumentError(
          "left matrix width does not match YPIR pad row count");
    }
    const int degree = ntt_->degree();
    VMatrix output(left.rows, degree);
    std::vector<uint32_t> coefficients(degree);
    for (uint64_t row = 0; row < left.rows; ++row) {
      auto accumulator = ntt_->ZeroNtt();
      for (int block = 0; block < params_.main_pad_block_count; ++block) {
        for (int i = 0; i < degree; ++i) {
          coefficients[i] = left.getElem(row, block * degree + i) %
                            kMainModulus;
        }
        RLWE_ASSIGN_OR_RETURN(auto left_ntt, ntt_->Forward(coefficients));
        RLWE_RETURN_IF_ERROR(ntt_->FusedMultiplyAddInPlace(
            accumulator, left_ntt, blocks_ntt_[block]));
      }
      RLWE_ASSIGN_OR_RETURN(auto result, ntt_->Inverse(accumulator));
      std::copy(result.begin(), result.end(), output.data + row * degree);
    }
    return output;
  }

  MainPreprocessorMetadata Metadata() const override {
    return YpirMetadata(params_);
  }

  const lwe::Matrix* DensePadIfMaterialized() const override {
    return nullptr;
  }

  absl::StatusOr<lwe::Matrix> MaterializePadForTesting() const override {
    const int degree = ntt_->degree();
    lwe::Matrix output(params_.db_cols, degree);
    for (int block = 0; block < params_.main_pad_block_count; ++block) {
      for (int row = 0; row < degree; ++row) {
        for (int col = 0; col < degree; ++col) {
          const int delta = col - row;
          output(block * degree + row, col) =
              delta >= 0 ? blocks_[block][delta]
                         : NegateMod(blocks_[block][degree + delta]);
        }
      }
    }
    return output;
  }

 private:
  YpirMainPreprocessor(
      Parameters params, std::unique_ptr<lwe::NegacyclicNtt> ntt,
      std::vector<std::vector<uint32_t>> blocks,
      std::vector<lwe::NegacyclicNtt::Polynomial> blocks_ntt,
      std::vector<lwe::NegacyclicNtt::Polynomial> transpose_blocks_ntt)
      : params_(std::move(params)),
        ntt_(std::move(ntt)),
        blocks_(std::move(blocks)),
        blocks_ntt_(std::move(blocks_ntt)),
        transpose_blocks_ntt_(std::move(transpose_blocks_ntt)) {}

  const Parameters params_;
  const std::unique_ptr<lwe::NegacyclicNtt> ntt_;
  const std::vector<std::vector<uint32_t>> blocks_;
  const std::vector<lwe::NegacyclicNtt::Polynomial> blocks_ntt_;
  const std::vector<lwe::NegacyclicNtt::Polynomial> transpose_blocks_ntt_;
};

}  // namespace

absl::StatusOr<MainPreprocessorMetadata> DescribeMainPreprocessor(
    const Parameters& params) {
  if (kMainModulus == 0 || kMainModulus > UINT32_MAX) {
    return absl::FailedPreconditionError(
        "main preprocessing requires the configured 32-bit Solinas prime");
  }
  if (params.main_preprocessor_backend ==
      MainPreprocessorBackend::kDenseLwe) {
    return DenseMetadata(params);
  }
  if (params.main_preprocessor_backend !=
      MainPreprocessorBackend::kYpirNtt) {
    return absl::InvalidArgumentError("unknown main preprocessing backend");
  }
  if (params.main_ring_log_n <= 0 || params.main_ring_log_n >= 31) {
    return absl::InvalidArgumentError(
        "YPIR main ring log degree must be in [1, 30]");
  }
  const int degree = 1 << params.main_ring_log_n;
  if (params.lwe_secret_dim != degree) {
    return absl::InvalidArgumentError(absl::StrCat(
        "YPIR main requires lwe_secret_dim == ring degree; got ",
        params.lwe_secret_dim, " and ", degree));
  }
  if (params.db_cols % degree != 0) {
    return absl::InvalidArgumentError(
        "YPIR main requires db_cols to be divisible by ring degree");
  }
  const int block_count = params.db_cols / degree;
  if (params.main_pad_block_count != block_count) {
    return absl::InvalidArgumentError(absl::StrCat(
        "YPIR main pad block count mismatch: got ",
        params.main_pad_block_count, ", derived ", block_count));
  }
  if (params.structured_pad_version != kYpirStructuredPadVersion) {
    return absl::InvalidArgumentError(
        "unsupported YPIR structured pad version");
  }
  return YpirMetadata(params);
}

absl::StatusOr<std::unique_ptr<MainPreprocessor>> CreateMainPreprocessor(
    const Parameters& params, absl::string_view public_seed) {
  RLWE_ASSIGN_OR_RETURN(const MainPreprocessorMetadata metadata,
                        DescribeMainPreprocessor(params));
  if (metadata.backend == MainPreprocessorBackend::kDenseLwe) {
    RLWE_ASSIGN_OR_RETURN(auto dense,
                          DenseMainPreprocessor::Create(params, public_seed));
    return std::unique_ptr<MainPreprocessor>(std::move(dense));
  }
  if (metadata.backend == MainPreprocessorBackend::kYpirNtt) {
    RLWE_ASSIGN_OR_RETURN(auto ypir,
                          YpirMainPreprocessor::Create(params, public_seed));
    return std::unique_ptr<MainPreprocessor>(std::move(ypir));
  }
  return absl::InvalidArgumentError("unknown main preprocessing backend");
}

}  // namespace hintless_simplepir
}  // namespace hintless_pir
