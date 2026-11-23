/*
 * Modified by Mayank Rathee
 * Copyright 2024 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HINTLESS_PIR_HINTLESS_SIMPLEPIR_PARAMETERS_H_
#define HINTLESS_PIR_HINTLESS_SIMPLEPIR_PARAMETERS_H_

#include <cstdint>

#include "linpir/parameters.h"
#include "lwe/types.h"
#include "shell_encryption/serialization.pb.h"

namespace hintless_pir {
namespace hintless_simplepir {

// Selects the implementation of the public matrix used by the main
// SimplePIR branch.  The dense backend is deliberately the zero value so that
// existing aggregate initializers keep their original behaviour.
enum class MainPreprocessorBackend : int {
  kDenseLwe = 0,
  kYpirNtt = 1,
};

// Selects the public matrix implementation used by the offline verification
// LWE instance that computes H_2 = D^T A_2.
enum class OfflinePreprocessorBackend : int {
  kDenseLwe = 0,
  kYpirNtt = 1,
};

// Parameters of the hintless SimplePIR protocol.
struct Parameters {
  using LweInteger = lwe::Integer;
  using RlweInteger = linpir::Uint64;

  int64_t db_rows;
  int64_t db_cols;
  int db_record_bit_size;

  int lwe_secret_dim;
  int offline_lwe_secret_dim;
  int lwe_modulus_bit_size;  // 32 or 64
  int lwe_plaintext_bit_size;
  int db_stack_cells;
  double lwe_error_variance;

  linpir::RlweParameters<RlweInteger> linpir_params;

  rlwe::PrngType prng_type;

  // Main preprocessing backend parameters.  They are ignored by kDenseLwe.
  MainPreprocessorBackend main_preprocessor_backend =
      MainPreprocessorBackend::kDenseLwe;
  int main_ring_log_n = 0;
  int main_pad_block_count = 0;
  int structured_pad_version = 0;

  // Offline verification preprocessing parameters.  The dense backend keeps
  // the legacy 2816-dimensional LWE implementation unchanged.
  OfflinePreprocessorBackend offline_preprocessor_backend =
      OfflinePreprocessorBackend::kDenseLwe;
  int offline_ring_log_n = 0;
  int offline_pad_block_count = 0;
  int offline_structured_pad_version = 0;
};

}  // namespace hintless_simplepir
}  // namespace hintless_pir

#endif  // HINTLESS_PIR_HINTLESS_SIMPLEPIR_PARAMETERS_H_
