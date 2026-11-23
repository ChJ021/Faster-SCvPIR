// Modified by Mayank Rathee
// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "hintless_simplepir/simplepir.h"
#include "verisimplepir/src/lib/pir/preproc_pir.h"
#include "verisimplepir/src/lib/pir/pir.h"

#include <cerrno>
#include <cstdlib>
#include <memory>
#include <cstring>
#include <limits>
#include <string>
#include <tuple>
#include <utility>
#include <iostream>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "lwe/types.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/testing/status_matchers.h"
#include "shell_encryption/testing/status_testing.h"
#include "lwe/matrix_conversion.h"
#include "hintless_simplepir/client.h"
#include "hintless_simplepir/database_hwy.h"
#include "hintless_simplepir/offline_preprocessor.h"
#include "hintless_simplepir/parameters.h"
#include "hintless_simplepir/server.h"
#include "linpir/parameters.h"

namespace hintless_pir {

namespace hintless_simplepir {
namespace {

using RlweInteger = Parameters::RlweInteger;

const int rows_db = 2048;
const int cols_db = 1024;
bool use_static_db = true;

Parameters kParameters{
    .db_rows = rows_db,
    .db_cols = cols_db,
    .db_record_bit_size = 8, // Don't include stacking here.
    .lwe_secret_dim = 1408,
    .offline_lwe_secret_dim = 2816,
    .lwe_modulus_bit_size = 32,
    .lwe_plaintext_bit_size = 8, // <= 8
    .db_stack_cells = 1,
    .lwe_error_variance = 8,
    .linpir_params =
        linpir::RlweParameters<RlweInteger>{
            .log_n = 12,
            .qs = {19988226643746817ULL, 19988226643402753ULL},
#ifdef SH_RUN
            .ts = {2056193, 1990657},
#else //SH_RUN
            .ts = {SOL_NTT_PRIME},
#endif //SH_RUN
            .gadget_log_bs = {13, 14},
            .error_variance = 8,
            .prng_type = rlwe::PRNG_TYPE_HKDF,
#ifdef BSGS
            .rows_per_block = std::min(rows_db, 2048),
#else //BSGS
            .rows_per_block = 1024, // From HintlessPIR
#endif //BSGS
            .db_rows = rows_db, // Need for BSGS optimality computation
        },
    .prng_type = rlwe::PRNG_TYPE_HKDF,
};

std::string preproc_profile = "baseline";
std::string database_profile = "legacy-smoke-2mib";

// Client's query index. This is database entry that the client will access via PIR
uint64_t index = cols_db - 4; // 4-th column from the right starting at 0th row (indexing from 0).

// All recorded metrics
#define HINT_MB "Hints (MiB)"
#define ONLINE_STATE_KB "Online State (KiB)"
#define OFFLINE_UP_KB "Offline Up (KiB)"
#define OFFLINE_DOWN_KB "Offline Down (KiB)"
#define PREPARE_UP_KB "Prep Up (Kib)"
#define PREPARE_DOWN_KB "Prep Down (KiB)"
#define QUERY_UP_KB "Query Up (KiB)"
#define QUERY_DOWN_KB "Query Down (KiB)"
#define GLOBAL_PREPR_S "Global Prepr (s)"
#define SV_CLIENT_SPEC_PREPR_S "Server Per-Client Prepr (s)"
#define CLIENT_PREPR_S "Client Local Prepr (s)"
#define CLIENT_PREP_PRE_S "Client Prepa Pre Req (s)"
#define SERVER_PREP_S "Server Prepa Comp (s)"
#define CLIENT_PREP_POST_S "Client Prepa Post Req (s)"
#define CLIENT_Q_REQ_GEN_MS "Query: Client Req Gen (ms)"
#define SERVER_Q_RESP_S "Query: Server Comp (s)"
#define CLIENT_Q_DEC_MS "Query: Client Decryption (ms)"
#define CLIENT_Q_VER_MS "Query: Client Verification (ms)"
#define LONG_TERM_STATE_KB "Long Term State (KiB)"
#define MAIN_PAD_BACKEND_STATE_KB "Main Pad Backend State (KiB)"
#define MAIN_PAD_PUBLIC_SEED_BYTES "Main Pad Public Seed (bytes)"

bool IsImportantStage0Timing(const char* stage) {
  static constexpr const char* kImportantStages[] = {
      "main_preprocess_bsgs_call",
      "client_create",
      "offline_A2_generate",
      "offline_H2_matrix_product",
      "offline_challenge_encrypt",
      "offline_DT_ciphertexts_product",
      "offline_recover_Z",
      "total",
      "offline_rebuild_main_pad_and_verify_ZA_equals_CH",
      "main_pad_rebuild_and_times_secret",
      "database_Du",
      "total_without_prepare",
  };
  for (const char* important_stage : kImportantStages) {
    if (std::strcmp(stage, important_stage) == 0) {
      return true;
    }
  }
  return false;
}

void PrintStage0Timing(const char* scope, const char* stage,
                       double start_ms, double end_ms) {
  if (!IsImportantStage0Timing(stage)) {
    return;
  }
  const double duration_ms = end_ms - start_ms;
  std::cout << "[STAGE0_TIMING] scope=" << scope << " stage=" << stage
            << " duration_ms=" << duration_ms
            << " duration_s=" << duration_ms / 1000 << std::endl;
}

TEST(HintlessSimplePir, EndToEndPIRTest) {
  // Some calculation around client's query index given how database is laid out
  uint64_t row_idx_start = index / kParameters.db_cols;
  if (row_idx_start % kParameters.db_stack_cells != 0) {
    std::cout << "\n\nError: row index not divisible by stack cells\n\n" << std::endl;
    assert(false);
  }
  uint64_t row_idx_end = row_idx_start + kParameters.db_stack_cells;
  uint64_t col_idx = index % kParameters.db_cols;

  // Important metrics
  map<string, double> dict;
  dict[HINT_MB] = 0; // mb is MiB, kb is KiB, s is sec, ms is ms
  dict[ONLINE_STATE_KB] = 0;
  dict[OFFLINE_UP_KB] = 0;
  dict[OFFLINE_DOWN_KB] = 0;
  dict[PREPARE_UP_KB] = 0;
  dict[PREPARE_DOWN_KB] = 0;
  dict[QUERY_UP_KB] = 0;
  dict[QUERY_DOWN_KB] = 0;
  dict[GLOBAL_PREPR_S] = 0;
  dict[SV_CLIENT_SPEC_PREPR_S] = 0;
  dict[CLIENT_PREPR_S] = 0;
  dict[CLIENT_PREP_PRE_S] = 0;
  dict[SERVER_PREP_S] = 0;
  dict[CLIENT_PREP_POST_S] = 0;
  dict[CLIENT_Q_REQ_GEN_MS] = 0;
  dict[SERVER_Q_RESP_S] = 0;
  dict[CLIENT_Q_DEC_MS] = 0;
  dict[CLIENT_Q_VER_MS] = 0;
  dict[LONG_TERM_STATE_KB] = 0;
  dict[MAIN_PAD_BACKEND_STATE_KB] = 0;
  dict[MAIN_PAD_PUBLIC_SEED_BYTES] = 0;

  const uint64_t row_in = kParameters.db_rows;
  const uint64_t col_in = kParameters.db_cols;
  const uint64_t lattice_n_in = kParameters.lwe_secret_dim;
  const uint64_t offline_lattice_n_in = kParameters.offline_lwe_secret_dim;
  const uint64_t d_in = kParameters.db_record_bit_size;
  const uint64_t N = row_in * col_in;
  const uint64_t logp_in = kParameters.lwe_plaintext_bit_size;

  std::cout << "Input params: N = " << N << " d = " << d_in << std::endl;
  std::cout << "database_profile=" << database_profile << std::endl;
  std::cout << "database_rows=" << kParameters.db_rows << std::endl;
  std::cout << "database_columns=" << kParameters.db_cols << std::endl;
  std::cout << "query_index=" << index << std::endl;
  std::cout << "database size: " << N*d_in / (8.0*(1ULL<<30)) << " GiB\n";
  std::cout << "Rows per block: " << kParameters.linpir_params.rows_per_block << std::endl;
  std::cout << "Shards: " << kParameters.db_record_bit_size / kParameters.lwe_plaintext_bit_size << " and Stacks: " << kParameters.db_stack_cells << std::endl;

#ifdef BSGS
  std::cout << "-----   Using BSGS   -----\n" << std::endl;
  if (kParameters.db_rows % kParameters.linpir_params.rows_per_block != 0) {
    std::cout << "ERROR: rows_per_block must divide db_rows" << std::endl;
    assert(false);
  }
#endif //BSGS

#ifdef FAKE_RUN
  std::cout << "-----   Fake Run   -----" << std::endl;
#endif //FAKE_RUN

#ifdef SH_RUN
  std::cout << "-----   Semi-Honest Run   -----" << std::endl;
#endif //SH_RUN

  double start, start2, start_prep, start_on, end, end2, end_prep, end_on;

	// Create VSPIR Object
  VeriSimplePIR pir(row_in, col_in, lattice_n_in, d_in, logp_in, true, false, false, false, 1, true, false);
  //std::cout << "Database params: "; pir.dbParams.print();

  // Create server and fill in random database records.
  std::unique_ptr<Server> server;

  start = currentDateTime();
#ifdef FAKE_RUN
  std::cout << "Using fake DB; correctness won't hold; this is only for evaluation" << std::endl;
  ASSERT_OK_AND_ASSIGN(server,
                       Server::CreateWithRandomDatabaseRecordsFake(kParameters));
#else //FAKE_RUN
  if (use_static_db) {
    std::cout << "Using static DB" << std::endl;
    ASSERT_OK_AND_ASSIGN(server,
                       Server::CreateWithFastDatabaseRecords(kParameters));
  }
  else { // use random DB
    std::cout << "Using random DB" << std::endl;
    ASSERT_OK_AND_ASSIGN(server,
                       Server::CreateWithRandomDatabaseRecords(kParameters));
  }
#endif //FAKE_RUN
  end = currentDateTime();
  PrintStage0Timing("global", "server_database_create_and_transpose", start,
                    end);

  const Database* database = server->GetDatabase();
  // Preprocess the server and get public parameters.
  start_prep = currentDateTime();
  start = currentDateTime();
#ifdef BSGS
  ASSERT_OK(server->PreprocessBSGS());
#else //BSGS
  ASSERT_OK(server->Preprocess());
#endif //BSGS
  end = currentDateTime();
  PrintStage0Timing("global", "main_preprocess_bsgs_call", start, end);
  // Server global preprocessing #1 (only main hint, i.e. overall LWE instance, and RLWE part) time
  dict[GLOBAL_PREPR_S] += (end-start)/1000;

  auto public_params = server->GetPublicParams();

  // Create a client and issue request.
  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto client, Client::Create(kParameters, public_params));
  end = currentDateTime();
  PrintStage0Timing("client_local", "client_create", start, end);
  dict[CLIENT_PREPR_S] += (end - start) / 1000;
  dict[MAIN_PAD_BACKEND_STATE_KB] =
      static_cast<double>(client->CachedMainPadBackendBytes()) /
      (1ULL << 10);
  dict[MAIN_PAD_PUBLIC_SEED_BYTES] =
      static_cast<double>(client->MainPadPublicSeedBytes());
  std::cout << "client_main_pad_backend_lifecycle="
               "ephemeral-per-operation"
            << std::endl;
  std::cout << "client_main_pad_backend_cached_bytes="
            << client->CachedMainPadBackendBytes() << std::endl;

  // This code moves back and forth between HintlessPIR code and VeriSimplePIR (VSPIR) code. So some type-casting is needed
  // Get A, H for VSPIR

  const double bridge_main_start = currentDateTime();
  start = bridge_main_start;
  // Get A, H from Hintless. The database stays in its packed column form:
  // the protocol never reads an expanded uint32 copy of D, and materializing
  // one costs four bytes per database cell (1 GiB for the 256 MiB layout).
  int num_shards = database->Data().size();
  end = currentDateTime();
  PrintStage0Timing("global", "bridge_export_database", start, end);

  start = currentDateTime();
  auto H_vec = database->Hints();

  // Convert H to VSPIR (directly rather than recomputing the hint).
  std::vector<VMatrix> H_vsp_vec;
  H_vsp_vec.reserve(num_shards);
  for (int i = 0; i < num_shards; i++) {
    VMatrix H_vsp(H_vec[0].size(), H_vec[0][0].size());
	  convertToVeriSimplePIRMatrixRowFormIn(H_vsp, H_vec[i]);
    H_vsp_vec.push_back(H_vsp);
  }
  // Main (overall LWE instance) hint size (MB)
  dict[HINT_MB] += (H_vsp_vec.size() * H_vsp_vec[0].rows * H_vsp_vec[0].cols * sizeof(Elem))/(1ULL << 20);
  end = currentDateTime();
  PrintStage0Timing("global", "bridge_convert_main_hint", start, end);
  // Server converting Hintless -> VeriSimplePIR time
  dict[GLOBAL_PREPR_S] += (end - bridge_main_start) / 1000;

	// Conversions done

#ifndef SH_RUN // Only run proof preprocessing if SH_RUN is not set

  const BinaryMatrix C = pir.PreprocSampleC();

  const double offline_A2_start = currentDateTime();
  start = offline_A2_start;
  const bool use_structured_offline =
      kParameters.offline_preprocessor_backend ==
      OfflinePreprocessorBackend::kYpirNtt;
  Matrix64 A_2;
  Database::LweMatrix64 A_2_hintless;
  std::unique_ptr<YpirOfflinePreprocessor> offline_preprocessor;
  if (use_structured_offline) {
    ASSERT_OK_AND_ASSIGN(
        offline_preprocessor,
        YpirOfflinePreprocessor::Create(
            kParameters, public_params.prng_seed_lwe_query_pad()));
  } else {
    A_2 = pir.PreprocInitNew64();
  }
  end = currentDateTime();
  PrintStage0Timing("global", "offline_A2_generate", start, end);
  start = currentDateTime();
  if (!use_structured_offline) {
	  A_2_hintless = convertToHintlessPIRMatrixColumnForm64(
        A_2, row_in, offline_lattice_n_in);
  }
  end = currentDateTime();
  PrintStage0Timing("global", "bridge_convert_offline_A2", start, end);
  // Expanding A_2 (A for offline-only LWE instance) time
  dict[GLOBAL_PREPR_S] += (end - offline_A2_start) / 1000;
  dict[CLIENT_PREPR_S] += (end - offline_A2_start) / 1000;

  //std::cout << "Computing H_2 = D^T * A_2" << std::endl;
  const double offline_H2_start = currentDateTime();
  start = offline_H2_start;
#ifdef FAKE_RUN
  auto H_2_hintless_vec = server->TransposeProductFake64();
#else //FAKE_RUN
  std::vector<Database::LweMatrix64> H_2_hintless_vec;
  if (use_structured_offline) {
    ASSERT_OK_AND_ASSIGN(H_2_hintless_vec,
                         offline_preprocessor->ComputeHint(*database));
  } else {
	  ASSERT_OK_AND_ASSIGN(H_2_hintless_vec,
                           server->TransposeProduct64(A_2_hintless));
  }
#endif //FAKE_RUN
  end = currentDateTime();
  PrintStage0Timing("global", "offline_H2_matrix_product", start, end);

  start = currentDateTime();
  std::vector<Matrix64> H_2_vec;
  H_2_vec.reserve(num_shards);
  for (int i = 0; i < num_shards; i++) {
    // Construct the row form in place: Matrix64 has no destructor, so a
    // temporary plus push_back copy would both be leaked in addition to the
    // stored matrix.
    H_2_vec.emplace_back(col_in, offline_lattice_n_in);
    convertToVeriSimplePIRMatrixRowFormIn64(H_2_vec.back(),
                                            H_2_hintless_vec[i]);
    // The hintless column form is dead after this conversion. Release it so
    // two full copies of H_2 are not held through the online phase.
    std::vector<Database::LweVector64>().swap(H_2_hintless_vec[i]);
  }
  end = currentDateTime();
  PrintStage0Timing("global", "bridge_convert_offline_H2", start, end);
  // Server global H_2 (hint for offline-only LWE instance) compute time
  dict[GLOBAL_PREPR_S] += (end - offline_H2_start) / 1000;
  // Large offline-only LWE's hint H_2 size (MB)
  dict[HINT_MB] += (H_2_vec.size() * H_2_vec[0].rows * H_2_vec[0].cols * sizeof(Elem64))/(1ULL << 20);

  //std::cout << "Encrypting challenge C for preprocessing phase" << std::endl;
  start = currentDateTime();
  std::pair<std::vector<Matrix64>, std::vector<Matrix64>>
      preproc_ct_sk_pair;
  if (use_structured_offline) {
    ASSERT_OK_AND_ASSIGN(
        preproc_ct_sk_pair,
        offline_preprocessor->EncryptChallenges(pir.lhe, C));
  } else {
    preproc_ct_sk_pair = pir.PreprocClientMessageNew64(A_2, C);
  }

  const auto preproc_cts = std::get<0>(preproc_ct_sk_pair);
  const auto preproc_sks = std::get<1>(preproc_ct_sk_pair);
  end = currentDateTime();
  PrintStage0Timing("client_local", "offline_challenge_encrypt", start, end);
  // Client encrypting C time
  dict[CLIENT_PREPR_S] += (end-start)/1000;
  // Client offline upload size (KB)
  dict[OFFLINE_UP_KB] += (preproc_cts.size() * preproc_cts[0].rows * preproc_cts[0].cols * sizeof(Elem64))/(1ULL << 10);

  //std::cout << "Computing v_i = D^T * u_i, for all i, in preprocessing" << std::endl;
  const double server_per_client_start = currentDateTime();
  start = server_per_client_start;
	auto preproc_cts_hintless = convertToHintlessPIRMatricesFromVectors64(preproc_cts, row_in);
  end = currentDateTime();
  PrintStage0Timing("server_per_client", "bridge_convert_challenge_ciphertexts",
                    start, end);
  start = currentDateTime();
	ASSERT_OK_AND_ASSIGN(auto D_T_ct, server->TransposeProductCiphertexts64(preproc_cts_hintless));
  end = currentDateTime();
  PrintStage0Timing("server_per_client", "offline_DT_ciphertexts_product",
                    start, end);
  start = currentDateTime();
  std::vector<std::vector<Matrix64>> preproc_res_cts_vec;
  preproc_res_cts_vec.reserve(num_shards);
  for (int i = 0; i < num_shards; i++) {
    auto preproc_res_cts = convertToVSPIRPIRVectors64(D_T_ct[i]);
    preproc_res_cts_vec.push_back(preproc_res_cts);
  }
  end = currentDateTime();
  PrintStage0Timing("server_per_client", "bridge_convert_offline_response",
                    start, end);
  // Server (client-specific) D^T*C^T time
  dict[SV_CLIENT_SPEC_PREPR_S] +=
      (end - server_per_client_start) / 1000;
  // Server offline response size (KB)
  dict[OFFLINE_DOWN_KB] += (preproc_res_cts_vec.size() * preproc_res_cts_vec[0].size() * preproc_res_cts_vec[0][0].rows * preproc_res_cts_vec[0][0].cols * sizeof(Elem64))/(1ULL << 10);

	//std::cout << "Decrypting Z in preprocessing phase" << std::endl;
  start = currentDateTime();
  std::vector<VMatrix> Z_vec;
  Z_vec.reserve(num_shards);
  for (int i = 0; i < num_shards; i++) {
    VMatrix Z = pir.PreprocRecoverZNew64(H_2_vec[i], preproc_sks, preproc_res_cts_vec[i], row_in);
    Z_vec.push_back(Z);
  }
  end = currentDateTime();
  PrintStage0Timing("client_local", "offline_recover_Z", start, end);
  // Client decrypting Z time
  dict[CLIENT_PREPR_S] += (end-start)/1000;

  //std::cout << "Sampling random vector for proof compression" << std::endl;
  start = currentDateTime();
  int rlc_count = DivideAndRoundUp(STAT_SEC_PARAM, LOG_Q);
  std::cout << "Proof compression: no. of rows in Z_prime = RC = " << rlc_count << std::endl;
  VMatrix R(rlc_count, STAT_SEC_PARAM);
  random(R, SOL_NTT_PRIME);

  //std::cout << "Compressing the challenge C" << std::endl;
  Matrix RC = matMulRightBinary(R, C);

  //std::cout << "Compressing the proof Z" << std::endl;
  std::vector<VMatrix> RZ_vec;
  RZ_vec.reserve(num_shards);
  for (int i = 0; i < num_shards; i++) {
    VMatrix RZ = matMul(R, Z_vec[i]);
    RZ_vec.push_back(RZ);
  }
  end = currentDateTime();
  PrintStage0Timing("client_local", "offline_compress_RC_RZ", start, end);
  // Client compression of Z time
  dict[CLIENT_PREPR_S] += (end-start)/1000;

  // Client compressed ZA=CH check
  start = currentDateTime();
  for (int i = 0; i < num_shards; i++) {
    ASSERT_OK_AND_ASSIGN(
        VMatrix RZA,
        client->MultiplyRightByMainPad(RZ_vec[i]));
    pir.VerifyPreprocZCompressedGivenLeftProduct(RZA, RC, H_vsp_vec[i]);
  }
  end = currentDateTime();
  PrintStage0Timing(
      "client_local",
      "offline_rebuild_main_pad_and_verify_ZA_equals_CH", start, end);
  // Client offline verification time
  dict[CLIENT_PREPR_S] += (end-start)/1000;
  std::cout << "Success: (Compressed) Z in preprocessing verified and preprocessing phase done.\n";

  end_prep = currentDateTime();
  PrintStage0Timing("preprocessing", "total", start_prep, end_prep);
  std::cout << "[==> TIMER  <==] Total preprocessing (server + client compute) time: " << (end_prep-start_prep) << " ms | " << (end_prep-start_prep)/1000 << " sec" << std::endl;

#endif //SH_RUN

  // Long-term private state only includes the compressed proof RZ. RC and the
  // public main pad are regenerated when needed; no main-pad backend is cached
  // by the client.
  dict[LONG_TERM_STATE_KB] += (RZ_vec.size() * RZ_vec[0].rows * RZ_vec[0].cols * sizeof(Elem))/(1ULL << 10);

  // Query-level preprocessing/prepare + online phase

  start_on = currentDateTime(); // Captures time of query-level prepr + online

  // Prepare phase = query-level preprocessing
  double start_prepare, end_prepare;

  start_prepare = currentDateTime();
	// Generate HintlessPIR client request + output sk from Hintless to VSPIR
  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto As_s_tuple, client->Compute_A_times_s());
  end = currentDateTime();
  PrintStage0Timing("prepare_client", "main_pad_rebuild_and_times_secret",
                    start, end);
  // Client reconstruction of the selected public-pad backend and A*s.
  dict[CLIENT_PREP_PRE_S] += (end-start)/1000;

  auto As_vsp = std::get<0>(As_s_tuple);
  auto As = std::get<1>(As_s_tuple);
  auto s_lwe = std::get<2>(As_s_tuple);

  // Size of of A*s
  dict[ONLINE_STATE_KB] += (As_vsp.rows * As_vsp.cols * sizeof(Elem))/(1ULL << 10);
  // Size of of s_lwe
  dict[ONLINE_STATE_KB] += (s_lwe.Key().size() * sizeof(Elem))/(1ULL << 10);

  // Prepare RLWE parts
  // Client's RLWE request
  start = currentDateTime();
#ifdef BSGS
  ASSERT_OK_AND_ASSIGN(auto prepare_req, client->PrepareLinPirGivenS_BSGS(s_lwe));
#else //BSGS
  ASSERT_OK_AND_ASSIGN(auto prepare_req, client->PrepareLinPirGivenS(s_lwe));
#endif //BSGS
  end = currentDateTime();
  PrintStage0Timing("prepare_client", "linpir_prepare_request", start, end);
  // Client prepare req gen time
  dict[CLIENT_PREP_PRE_S] += (end-start)/1000;
  // Client prepare request KB
  dict[PREPARE_UP_KB] += (prepare_req.ByteSizeLong() / 1024);
  // Client prepare request (rotation keys, RLWE cipher of s_lwe) size
  dict[ONLINE_STATE_KB] += (prepare_req.ByteSizeLong() / 1024);

  // Server's RLWE response
  start = currentDateTime();
#ifdef BSGS
  ASSERT_OK_AND_ASSIGN(auto prepare_response, server->HandlePrepareRequestBSGS(prepare_req));
#else //BSGS
  ASSERT_OK_AND_ASSIGN(auto prepare_response, server->HandlePrepareRequest(prepare_req));
#endif //BSGS
  end = currentDateTime();
  PrintStage0Timing("prepare_server", "linpir_Hs_response", start, end);
  // Server prepare response time (LinPir H*s compute time)
  dict[SERVER_PREP_S] += (end-start)/1000;
  // Server prepare response KB
  dict[PREPARE_DOWN_KB] += (prepare_response.ByteSizeLong() / 1024);
  // Client prepare response from server (Hs) size
  dict[ONLINE_STATE_KB] += (prepare_response.ByteSizeLong() / 1024);

  // Client decrypt RLWE response
  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto hs_vec, client->RecoverHsPreparePhase(prepare_response));
  end = currentDateTime();
  PrintStage0Timing("prepare_client", "linpir_Hs_recover", start, end);
  // Client prepare recover time (LinPir response decryption)
  dict[CLIENT_PREP_POST_S] += (end-start)/1000;

#ifndef SH_RUN // Only run verification if SH_RUN is not set
  // Size of Z' = RZ
  dict[ONLINE_STATE_KB] += (RZ_vec.size() * RZ_vec[0].rows * RZ_vec[0].cols * sizeof(Elem))/(1ULL << 10);
  // Size of C' = RC
  dict[ONLINE_STATE_KB] += (RC.rows * RC.cols * sizeof(Elem))/(1ULL << 10);

  //std::cout << "Doing verification: H*s as part of prepare phase" << std::endl;
  start2 = currentDateTime();
  for (int i = 0; i < num_shards; i++) {
    VMatrix h_times_s = convertToVeriSimplePIRColumnMatrixSized(hs_vec[i], row_in);
    // Size of decrypted H*s (i.e. w)
    dict[ONLINE_STATE_KB] += (h_times_s.rows * h_times_s.cols * sizeof(Elem))/(1ULL << 10);
    // Verify
    pir.HsVerifyCompressed(As_vsp, h_times_s, RZ_vec[i], RC);
  }
  end2 = currentDateTime();
  PrintStage0Timing("prepare_client", "verify_Hs", start2, end2);
  // Client prepare verification of H*s time
  dict[CLIENT_PREP_POST_S] += (end2-start2)/1000;
#endif //SH_RUN

  end_prepare = currentDateTime();
  PrintStage0Timing("prepare", "total", start_prepare, end_prepare);
  std::cout << BLUE << "[==> TIMER  <==] Prepare phase (query-level preprocessing) total (client + server) time: " << (end_prepare-start_prepare) << " ms | " << (end_prepare-start_prepare)/1000 << " sec" << END << std::endl;

  double start_online, end_online;
  start_online = currentDateTime();
  lwe::Vector query_vsp = lwe::Vector::Zero(col_in);

  // Client online request gen
  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto request_and_query, client->GenerateRequestGivenAsSkipLinPir(index, As, s_lwe));
  end = currentDateTime();
  PrintStage0Timing("online_client", "query_generate", start, end);
  // Client online request generation time
  dict[CLIENT_Q_REQ_GEN_MS] += (end-start);

  auto request = request_and_query.first;
	auto query = request_and_query.second;
  // Client online request (LWE only) KB
  dict[QUERY_UP_KB] += (request.ByteSizeLong() / 1024);
  // Client request (LWE query only) size
  dict[ONLINE_STATE_KB] += (request.ByteSizeLong() / 1024);

	VMatrix query_vsp__ = convertToVeriSimplePIRColumnMatrix(query);

	// Server handles the online request
  start2 = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto response, server->HandleRequestSkipLinPir(request));
  end2 = currentDateTime();
  PrintStage0Timing("online_server", "database_Du", start2, end2);
  // Server-only online time (only D*u)
  dict[SERVER_Q_RESP_S] += (end2-start2)/1000;
  // Server online response KB
  dict[QUERY_DOWN_KB] += (response.ByteSizeLong() / 1024);
  // Client response from server (D*u) size
  dict[ONLINE_STATE_KB] += (response.ByteSizeLong() / 1024);

  // Client decrypts the online response
  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto rec_v, client->RecoverRecordAndGiveV(response, hs_vec));
  end = currentDateTime();
  PrintStage0Timing("online_client", "record_recover", start, end);
  // Client record recovery time (given precomputed Hs)
  dict[CLIENT_Q_DEC_MS] += (end-start);

  auto record = std::get<0>(rec_v);
	auto resp_vec = std::get<1>(rec_v);

#ifndef SH_RUN // Only run verification if SH_RUN is not set
  start = currentDateTime();
  //std::cout << "Doing verification: D*u" << std::endl;
  for (int i = 0; i < num_shards; i++) {
    auto response_vsp__ = convertToVeriSimplePIRColumnMatrixStdVec(resp_vec[i]);
    pir.PreVerifyCompressed(query_vsp__, response_vsp__, RZ_vec[i], RC);
  }
  //std::cout << "Online verification done for all shards" << std::endl;
  end = currentDateTime();
  PrintStage0Timing("online_client", "verify_Du", start, end);
  // Client online verification time (only D*u)
  dict[CLIENT_Q_VER_MS] += (end-start);
#endif //SH_RUN

  end_on = currentDateTime();
  std::cout << BLUE << "[==> TIMER  <==] Query-level preprocessing + online time: " << (end_on-start_on) << " ms | " << (end_on-start_on)/1000 << " sec" << END << std::endl;

  end_online = currentDateTime();
  PrintStage0Timing("online", "total_without_prepare", start_online,
                    end_online);
  std::cout << BLUE << "[==> TIMER  <==] Online-only (w/o prepare) phase total (client + server) time: " << (end_online-start_online) << " ms | " << (end_online-start_online)/1000 << " sec" << END << std::endl;

  if (kParameters.db_stack_cells > 1) { // Stacking
    ASSERT_OK_AND_ASSIGN(auto expected, database->RecordWithStacking(index));
    EXPECT_EQ(record, expected);
  }
  else {
    ASSERT_OK_AND_ASSIGN(auto expected, database->Record(index));
    EXPECT_EQ(record, expected);
  }
  std::cout << "End-to-end test done." << std::endl;

  std::cout << "----------------------------------" << std::endl;
  std::cout << "Recorded metrics" << std::endl;
  std::cout << "Database size: " << N*d_in / (8.0*(1ULL<<30)) << " GiB\n";
  std::cout << "Shards: " << kParameters.db_record_bit_size /
                                 kParameters.lwe_plaintext_bit_size << " and Stacks: " << kParameters.db_stack_cells << std::endl;
  for (auto it : dict) {
    std::cout << it.first << " : " << it.second << std::endl;
  }

}

}  // namespace
}  // namespace hintless_simplepir

}  // namespace hintless_pir

int main(int argc, char** argv) {
  std::vector<char*> gtest_args;
  gtest_args.reserve(argc);
  gtest_args.push_back(argv[0]);
  std::string profile = "dense";
  std::string requested_database_profile = "legacy-smoke-2mib";
  int configured_rows = 2048;
  int configured_columns = 1024;
  int configured_record_bits = 8;
  int configured_stack_cells = 1;
  int offline_ring_degree = 4096;
  bool offline_ring_degree_explicit = false;
  uint64_t requested_query_index = 0;
  bool query_index_explicit = false;
  constexpr char kProfilePrefix[] = "--preproc-profile=";
  constexpr char kDatabaseProfilePrefix[] = "--database-profile=";
  constexpr char kDbRowsPrefix[] = "--db-rows=";
  constexpr char kDbColumnsPrefix[] = "--db-columns=";
  constexpr char kDbRecordBitsPrefix[] = "--db-record-bits=";
  constexpr char kDbStackCellsPrefix[] = "--db-stack-cells=";
  constexpr char kOfflineRingPrefix[] = "--offline-ring-degree=";
  constexpr char kQueryIndexPrefix[] = "--query-index=";
  auto parse_positive_int = [](const char* value, const char* flag,
                               int* out) -> bool {
    if (*value == '\0' || *value == '-') {
      std::cerr << flag << " must be a positive integer; got " << value
                << std::endl;
      return false;
    }
    char* end = nullptr;
    errno = 0;
    const long parsed = std::strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed <= 0 ||
        parsed > std::numeric_limits<int>::max()) {
      std::cerr << flag << " must be a positive integer; got " << value
                << std::endl;
      return false;
    }
    *out = static_cast<int>(parsed);
    return true;
  };
  for (int i = 1; i < argc; ++i) {
    if (std::strncmp(argv[i], kProfilePrefix,
                     sizeof(kProfilePrefix) - 1) == 0) {
      profile = argv[i] + sizeof(kProfilePrefix) - 1;
    } else if (std::strncmp(argv[i], kDatabaseProfilePrefix,
                            sizeof(kDatabaseProfilePrefix) - 1) == 0) {
      requested_database_profile =
          argv[i] + sizeof(kDatabaseProfilePrefix) - 1;
    } else if (std::strncmp(argv[i], kDbRowsPrefix,
                            sizeof(kDbRowsPrefix) - 1) == 0) {
      if (!parse_positive_int(argv[i] + sizeof(kDbRowsPrefix) - 1,
                              "--db-rows", &configured_rows)) {
        return 2;
      }
    } else if (std::strncmp(argv[i], kDbColumnsPrefix,
                            sizeof(kDbColumnsPrefix) - 1) == 0) {
      if (!parse_positive_int(argv[i] + sizeof(kDbColumnsPrefix) - 1,
                              "--db-columns", &configured_columns)) {
        return 2;
      }
    } else if (std::strncmp(argv[i], kDbRecordBitsPrefix,
                            sizeof(kDbRecordBitsPrefix) - 1) == 0) {
      if (!parse_positive_int(argv[i] + sizeof(kDbRecordBitsPrefix) - 1,
                              "--db-record-bits", &configured_record_bits)) {
        return 2;
      }
    } else if (std::strncmp(argv[i], kDbStackCellsPrefix,
                            sizeof(kDbStackCellsPrefix) - 1) == 0) {
      if (!parse_positive_int(argv[i] + sizeof(kDbStackCellsPrefix) - 1,
                              "--db-stack-cells", &configured_stack_cells)) {
        return 2;
      }
    } else if (std::strncmp(argv[i], kOfflineRingPrefix,
                            sizeof(kOfflineRingPrefix) - 1) == 0) {
      const std::string value =
          argv[i] + sizeof(kOfflineRingPrefix) - 1;
      if (value == "2048") {
        offline_ring_degree = 2048;
      } else if (value == "4096") {
        offline_ring_degree = 4096;
      } else {
        std::cerr << "--offline-ring-degree must be 2048 or 4096; got "
                  << value << std::endl;
        return 2;
      }
      offline_ring_degree_explicit = true;
    } else if (std::strncmp(argv[i], kQueryIndexPrefix,
                            sizeof(kQueryIndexPrefix) - 1) == 0) {
      const char* value = argv[i] + sizeof(kQueryIndexPrefix) - 1;
      if (*value == '\0' || *value == '-') {
        std::cerr << "--query-index must be an unsigned integer; got "
                  << value << std::endl;
        return 2;
      }
      char* end = nullptr;
      errno = 0;
      const unsigned long long parsed = std::strtoull(value, &end, 10);
      if (errno != 0 || end == value || *end != '\0' ||
          parsed > std::numeric_limits<uint64_t>::max()) {
        std::cerr << "--query-index must be an unsigned integer; got "
                  << value << std::endl;
        return 2;
      }
      requested_query_index = static_cast<uint64_t>(parsed);
      query_index_explicit = true;
    } else {
      gtest_args.push_back(argv[i]);
    }
  }

  using hintless_pir::hintless_simplepir::MainPreprocessorBackend;
  using hintless_pir::hintless_simplepir::OfflinePreprocessorBackend;
  using hintless_pir::hintless_simplepir::database_profile;
  using hintless_pir::hintless_simplepir::index;
  using hintless_pir::hintless_simplepir::kParameters;
  using hintless_pir::hintless_simplepir::kYpirOfflineStructuredPadVersion;
  using hintless_pir::hintless_simplepir::kYpirStructuredPadVersion;
  using hintless_pir::hintless_simplepir::preproc_profile;
  bool main_ypir = false;
  bool offline_ypir = false;

  if (profile == "baseline") profile = "dense";
  if (profile == "ypir-main") profile = "negacyclic-main";
  if (profile == "distpir-offline") profile = "negacyclic-offline";
  if (profile == "hybrid") profile = "negacyclic-both";

  if (requested_database_profile.empty()) {
    std::cerr << "--database-profile must not be empty" << std::endl;
    return 2;
  }
  if (configured_rows % configured_stack_cells != 0) {
    std::cerr << "db rows must be divisible by stack cells; got "
              << configured_rows << " and " << configured_stack_cells
              << std::endl;
    return 2;
  }
  if (configured_record_bits % kParameters.lwe_plaintext_bit_size != 0) {
    std::cerr << "db record bits must be a multiple of the LWE plaintext "
                 "bit size; got "
              << configured_record_bits << " and "
              << kParameters.lwe_plaintext_bit_size << std::endl;
    return 2;
  }
  kParameters.db_rows = configured_rows;
  kParameters.db_cols = configured_columns;
  kParameters.db_record_bit_size = configured_record_bits;
  kParameters.db_stack_cells = configured_stack_cells;
  kParameters.linpir_params.rows_per_block =
      std::min(configured_rows, 2048);
  kParameters.linpir_params.db_rows = configured_rows;
  database_profile = requested_database_profile;

  const uint64_t total_cells =
      static_cast<uint64_t>(configured_rows) * configured_columns;
  index = query_index_explicit
              ? requested_query_index
              : static_cast<uint64_t>(configured_columns - 4);
  if (index >= total_cells) {
    std::cerr << "query index " << index << " is outside [0, "
              << total_cells << ")" << std::endl;
    return 2;
  }
  const uint64_t query_row = index / configured_columns;
  if (query_row % configured_stack_cells != 0 ||
      query_row + configured_stack_cells >
          static_cast<uint64_t>(configured_rows)) {
    std::cerr << "query index " << index
              << " is not aligned to the configured stack of "
              << configured_stack_cells << " cells" << std::endl;
    return 2;
  }

  auto configure_main_ypir = [&]() -> bool {
    constexpr int kYpirRingLogN = 11;
    constexpr int kYpirRingDegree = 1 << kYpirRingLogN;
    if (kParameters.db_cols % kYpirRingDegree != 0) {
      std::cerr << "YPIR main requires db_cols divisible by 2048; got "
                << kParameters.db_cols << std::endl;
      return false;
    }
    kParameters.lwe_secret_dim = kYpirRingDegree;
    kParameters.main_preprocessor_backend =
        MainPreprocessorBackend::kYpirNtt;
    kParameters.main_ring_log_n = kYpirRingLogN;
    kParameters.main_pad_block_count =
        kParameters.db_cols / kYpirRingDegree;
    kParameters.structured_pad_version = kYpirStructuredPadVersion;
    main_ypir = true;
    return true;
  };

  auto configure_offline_ypir = [&]() -> bool {
    if (kParameters.db_rows % offline_ring_degree != 0) {
      std::cerr << "YPIR offline requires db_rows divisible by "
                << offline_ring_degree << "; got " << kParameters.db_rows
                << std::endl;
      return false;
    }
    kParameters.offline_lwe_secret_dim = offline_ring_degree;
    kParameters.offline_preprocessor_backend =
        OfflinePreprocessorBackend::kYpirNtt;
    kParameters.offline_ring_log_n =
        offline_ring_degree == 2048 ? 11 : 12;
    kParameters.offline_pad_block_count =
        kParameters.db_rows / offline_ring_degree;
    kParameters.offline_structured_pad_version =
        kYpirOfflineStructuredPadVersion;
    offline_ypir = true;
    return true;
  };

  if (profile == "dense") {
    kParameters.main_preprocessor_backend =
        MainPreprocessorBackend::kDenseLwe;
  } else if (profile == "negacyclic-main") {
    if (!configure_main_ypir()) return 2;
  } else if (profile == "negacyclic-offline") {
    if (!configure_offline_ypir()) return 2;
  } else if (profile == "negacyclic-both") {
    if (!configure_main_ypir() || !configure_offline_ypir()) return 2;
  } else {
    std::cerr << "unknown --preproc-profile value: " << profile << std::endl;
    return 2;
  }
  if (!offline_ypir && offline_ring_degree_explicit) {
    std::cerr << "--offline-ring-degree is only valid for negacyclic-offline "
                 "and negacyclic-both profiles"
              << std::endl;
    return 2;
  }
  preproc_profile = profile;
  std::cout << "preproc_profile=" << preproc_profile << std::endl;
  std::cout << "main_preproc_backend="
            << (main_ypir ? "ypir-exact-ntt" : "dense-lwe")
            << std::endl;
  std::cout << "main_ring_degree="
            << (main_ypir ? 2048 : 0) << std::endl;
  std::cout << "main_pad_block_count="
            << (main_ypir ? kParameters.main_pad_block_count : 0)
            << std::endl;
  std::cout << "main_modulus=" << SOL_NTT_PRIME << std::endl;
  if (main_ypir) {
    std::cout << "main_security_status="
                 "screen-pass-conditional-on-paper-reduction"
              << std::endl;
  } else {
    std::cout << "main_security_status=baseline-lwe-screen-pass"
              << std::endl;
  }
  std::cout << "offline_preproc_backend="
            << (offline_ypir ? "ypir-offline-exact-ntt" : "dense-offline")
            << std::endl;
  std::cout << "offline_ring_degree="
            << (offline_ypir ? offline_ring_degree : 0) << std::endl;
  std::cout << "offline_pad_block_count="
            << (offline_ypir ? kParameters.offline_pad_block_count : 0)
            << std::endl;
  std::cout << "offline_modulus=" << VSPIR_LHE_PRIME << std::endl;
  if (offline_ypir) {
    std::cout << "offline_prg_domain="
              << hintless_pir::hintless_simplepir::kYpirOfflinePadDomain
              << std::endl;
    std::cout << "offline_security_status="
                 "screen-pass"
              << std::endl;
  } else {
    std::cout << "offline_security_status=baseline-lwe-screen-pass"
              << std::endl;
  }
  std::cout << "bfv_security_status=screen-pass-minimal-margin"
            << std::endl;

  int gtest_argc = static_cast<int>(gtest_args.size());
  ::testing::InitGoogleTest(&gtest_argc, gtest_args.data());
  return RUN_ALL_TESTS();
}
