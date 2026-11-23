// Copyright 2026
// Licensed under the Apache License, Version 2.0.

#include "hintless_simplepir/offline_preprocessor.h"

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
#include "lwe/negacyclic_ntt.h"
#include "shell_encryption/prng/prng.h"
#include "shell_encryption/prng/single_thread_chacha_prng.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/status_macros.h"
#include "verisimplepir/src/lib/pir/lhe.h"

namespace hintless_pir {
namespace hintless_simplepir {
namespace {

constexpr uint64_t kOfflineModulus = VSPIR_LHE_PRIME;

uint64_t NegateMod(uint64_t value) {
  return value == 0 ? 0 : kOfflineModulus - value;
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
  return absl::InvalidArgumentError("unsupported PRNG for offline public pad");
}

absl::StatusOr<std::string> DeriveOfflinePadSeed(
    const Parameters& params, absl::string_view public_seed) {
  size_t output_length;
  if (params.prng_type == rlwe::PRNG_TYPE_HKDF) {
    output_length = rlwe::SingleThreadHkdfPrng::SeedLength();
  } else if (params.prng_type == rlwe::PRNG_TYPE_CHACHA) {
    output_length = rlwe::SingleThreadChaChaPrng::SeedLength();
  } else {
    return absl::InvalidArgumentError("unsupported PRNG for offline pad seed");
  }
  if (output_length > SHA512_DIGEST_LENGTH) {
    return absl::InternalError("offline pad seed length exceeds SHA-512 output");
  }
  std::string input;
  input.reserve(sizeof(kYpirOfflinePadDomain) + public_seed.size());
  input.append(kYpirOfflinePadDomain);
  input.push_back('\0');
  input.append(public_seed.data(), public_seed.size());
  std::array<unsigned char, SHA512_DIGEST_LENGTH> digest{};
  SHA512(reinterpret_cast<const unsigned char*>(input.data()), input.size(),
         digest.data());
  return std::string(reinterpret_cast<const char*>(digest.data()),
                     output_length);
}

absl::StatusOr<uint64_t> SampleUniformCoefficient(rlwe::SecurePrng* prng) {
  static_assert(VSPIR_LHE_PRIME_BITS > 0 && VSPIR_LHE_PRIME_BITS < 64,
                "offline modulus bit size must be in [1, 63]");
  constexpr uint64_t kMask =
      (uint64_t{1} << VSPIR_LHE_PRIME_BITS) - uint64_t{1};
  uint64_t candidate;
  do {
    RLWE_ASSIGN_OR_RETURN(candidate, prng->Rand64());
    candidate &= kMask;
  } while (candidate >= kOfflineModulus);
  return candidate;
}

}  // namespace

absl::StatusOr<std::unique_ptr<YpirOfflinePreprocessor>>
YpirOfflinePreprocessor::Create(const Parameters& params,
                                absl::string_view public_seed) {
  if (params.offline_preprocessor_backend !=
      OfflinePreprocessorBackend::kYpirNtt) {
    return absl::InvalidArgumentError(
        "YPIR offline preprocessor requires the YPIR NTT backend");
  }
  if (params.offline_ring_log_n <= 0 || params.offline_ring_log_n >= 31) {
    return absl::InvalidArgumentError(
        "YPIR offline ring log degree must be in [1, 30]");
  }
  const int degree = 1 << params.offline_ring_log_n;
  if (params.offline_lwe_secret_dim != degree) {
    return absl::InvalidArgumentError(absl::StrCat(
        "YPIR offline requires offline_lwe_secret_dim == ring degree; got ",
        params.offline_lwe_secret_dim, " and ", degree));
  }
  if (params.db_rows % degree != 0) {
    return absl::InvalidArgumentError(
        "YPIR offline requires db_rows to be divisible by ring degree");
  }
  const int block_count = params.db_rows / degree;
  if (params.offline_pad_block_count != block_count) {
    return absl::InvalidArgumentError(absl::StrCat(
        "YPIR offline pad block count mismatch: got ",
        params.offline_pad_block_count, ", derived ", block_count));
  }
  if (params.offline_structured_pad_version !=
      kYpirOfflineStructuredPadVersion) {
    return absl::InvalidArgumentError(
        "unsupported YPIR offline structured pad version");
  }
  if (params.lwe_plaintext_bit_size <= 0 ||
      params.lwe_plaintext_bit_size > 8) {
    return absl::InvalidArgumentError(
        "YPIR offline requires database coefficients of at most 8 bits");
  }

  RLWE_ASSIGN_OR_RETURN(
      auto ntt,
      lwe::NegacyclicNtt::Create(kOfflineModulus,
                                 params.offline_ring_log_n));
  RLWE_ASSIGN_OR_RETURN(const std::string domain_seed,
                        DeriveOfflinePadSeed(params, public_seed));
  RLWE_ASSIGN_OR_RETURN(auto prng, CreatePadPrng(params, domain_seed));

  std::vector<std::vector<uint64_t>> blocks(
      block_count, std::vector<uint64_t>(degree));
  std::vector<lwe::NegacyclicNtt::Polynomial> blocks_ntt;
  std::vector<lwe::NegacyclicNtt::Polynomial> transpose_blocks_ntt;
  blocks_ntt.reserve(block_count);
  transpose_blocks_ntt.reserve(block_count);
  for (int block = 0; block < block_count; ++block) {
    for (int i = 0; i < degree; ++i) {
      RLWE_ASSIGN_OR_RETURN(blocks[block][i],
                            SampleUniformCoefficient(prng.get()));
    }
    RLWE_ASSIGN_OR_RETURN(auto block_ntt, ntt->Forward64(blocks[block]));
    blocks_ntt.push_back(std::move(block_ntt));

    // If NC(a)[i,j] = a[j-i] with negacyclic wrap, then NC(a)*s is
    // the negacyclic convolution of (a0,-aN-1,...,-a1) with s.
    std::vector<uint64_t> transposed(degree);
    transposed[0] = blocks[block][0];
    for (int i = 1; i < degree; ++i) {
      transposed[i] = NegateMod(blocks[block][degree - i]);
    }
    RLWE_ASSIGN_OR_RETURN(auto transpose_ntt,
                          ntt->Forward64(transposed));
    transpose_blocks_ntt.push_back(std::move(transpose_ntt));
  }

  return absl::WrapUnique(new YpirOfflinePreprocessor(
      params, std::move(ntt), std::move(blocks), std::move(blocks_ntt),
      std::move(transpose_blocks_ntt)));
}

absl::StatusOr<std::vector<Database::LweMatrix64>>
YpirOfflinePreprocessor::ComputeHint(const Database& database) const {
  absl::Span<const Database::RawMatrix> shards = database.Data();
  if (shards.size() != database.NumShards()) {
    return absl::InternalError("database shard count mismatch");
  }
  std::vector<Database::LweMatrix64> output(shards.size());
  const int degree = ntt_->degree();
  const int values_per_word =
      sizeof(Database::BlockType) / sizeof(lwe::DBInteger);
  const int bits_per_value = 8 * sizeof(lwe::DBInteger);
  const uint64_t db_mask =
      (uint64_t{1} << params_.lwe_plaintext_bit_size) - uint64_t{1};

  for (size_t shard = 0; shard < shards.size(); ++shard) {
    if (shards[shard].size() != params_.db_cols) {
      return absl::InvalidArgumentError(
          "database column-form width does not match database parameters");
    }
    Database::LweMatrix64& hint = output[shard];
    hint.resize(params_.db_cols);
    std::vector<uint64_t> coefficients(degree);
    for (int64_t col = 0; col < params_.db_cols; ++col) {
      if (shards[shard][col].size() * values_per_word < params_.db_rows) {
        return absl::InvalidArgumentError(
            "packed database column is too short");
      }
      auto accumulator = ntt_->ZeroNtt();
      for (int block = 0; block < params_.offline_pad_block_count; ++block) {
        const int64_t base_row = static_cast<int64_t>(block) * degree;
        for (int i = 0; i < degree; ++i) {
          const int64_t row = base_row + i;
          const int64_t word = row / values_per_word;
          const int shift = (row % values_per_word) * bits_per_value;
          coefficients[i] = static_cast<uint64_t>(
              (shards[shard][col][word] >> shift) & db_mask);
        }
        RLWE_ASSIGN_OR_RETURN(auto data_ntt,
                              ntt_->Forward64(coefficients));
        RLWE_RETURN_IF_ERROR(ntt_->FusedMultiplyAddInPlace(
            accumulator, data_ntt, blocks_ntt_[block]));
      }
      RLWE_ASSIGN_OR_RETURN(hint[col], ntt_->Inverse64(accumulator));
    }
  }
  return output;
}

absl::StatusOr<Matrix64> YpirOfflinePreprocessor::ComputePadTimesSecret(
    const Matrix64& secret) const {
  const int degree = ntt_->degree();
  if (secret.rows != static_cast<uint64_t>(degree) || secret.cols != 1) {
    return absl::InvalidArgumentError(
        "secret dimensions do not match YPIR offline ring degree");
  }
  std::vector<uint64_t> secret_coefficients(degree);
  for (int i = 0; i < degree; ++i) {
    if (secret.data[i] >= kOfflineModulus) {
      return absl::InvalidArgumentError(
          "secret coefficient is not in canonical Z_q representation");
    }
    secret_coefficients[i] = secret.data[i];
  }
  RLWE_ASSIGN_OR_RETURN(auto secret_ntt,
                        ntt_->Forward64(secret_coefficients));
  Matrix64 output(params_.db_rows, 1);
  for (int block = 0; block < params_.offline_pad_block_count; ++block) {
    auto product = transpose_blocks_ntt_[block];
    RLWE_RETURN_IF_ERROR(ntt_->MultiplyInPlace(product, secret_ntt));
    RLWE_ASSIGN_OR_RETURN(auto coefficients, ntt_->Inverse64(product));
    for (int i = 0; i < degree; ++i) {
      output.data[static_cast<uint64_t>(block) * degree + i] = coefficients[i];
    }
  }
  return output;
}

absl::StatusOr<std::pair<std::vector<Matrix64>, std::vector<Matrix64>>>
YpirOfflinePreprocessor::EncryptChallenges(
    const LHE& lhe, const BinaryMatrix& plaintexts) const {
  if (plaintexts.cols != static_cast<uint64_t>(params_.db_rows)) {
    return absl::InvalidArgumentError(
        "offline challenge width does not match A_2 row count");
  }
  std::vector<Matrix64> secret_keys;
  secret_keys.reserve(plaintexts.rows);
  for (uint64_t row = 0; row < plaintexts.rows; ++row) {
    secret_keys.push_back(
        lhe.sampleSecretKeyTernary64(params_.offline_lwe_secret_dim));
  }

  std::vector<Matrix64> ciphertexts;
  ciphertexts.reserve(plaintexts.rows);
  for (uint64_t row = 0; row < plaintexts.rows; ++row) {
    Matrix64 plaintext(plaintexts.cols, 1);
    for (uint64_t i = 0; i < plaintexts.cols; ++i) {
      plaintext.data[i] = plaintexts.data[row * plaintexts.cols + i];
    }
    RLWE_ASSIGN_OR_RETURN(Matrix64 pad_times_secret,
                          ComputePadTimesSecret(secret_keys[row]));
    ciphertexts.push_back(
        lhe.encrypt64FromPadProduct(pad_times_secret, plaintext, true));
  }
  return std::make_pair(std::move(ciphertexts), std::move(secret_keys));
}

OfflinePreprocessorMetadata YpirOfflinePreprocessor::Metadata() const {
  return OfflinePreprocessorMetadata{
      .backend = OfflinePreprocessorBackend::kYpirNtt,
      .backend_name = "ypir-offline-exact-ntt",
      .ring_degree = ntt_->degree(),
      .pad_block_count = params_.offline_pad_block_count,
      .structured_pad_version = params_.offline_structured_pad_version,
      .modulus = kOfflineModulus,
      .secret_dimension = params_.offline_lwe_secret_dim,
      .prg_domain = kYpirOfflinePadDomain,
      .security_status = "experimental-ring-lwe-parameters-not-audited",
  };
}

absl::StatusOr<Matrix64>
YpirOfflinePreprocessor::MaterializePadForTesting() const {
  const int degree = ntt_->degree();
  Matrix64 output(params_.db_rows, degree);
  for (int block = 0; block < params_.offline_pad_block_count; ++block) {
    for (int row = 0; row < degree; ++row) {
      for (int col = 0; col < degree; ++col) {
        const int delta = col - row;
        output.data[(static_cast<uint64_t>(block) * degree + row) * degree +
                    col] = delta >= 0
                               ? blocks_[block][delta]
                               : NegateMod(blocks_[block][degree + delta]);
      }
    }
  }
  return output;
}

}  // namespace hintless_simplepir
}  // namespace hintless_pir
