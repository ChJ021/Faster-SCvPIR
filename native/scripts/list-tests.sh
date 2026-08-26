#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

pir_verify_upstream
pir_prepare_compiler
pir_resolve_bazel

readonly RUN_ID="$(pir_run_id)"
readonly LIST_LOG="$PIR_LOG_DIR/list-tests-$RUN_ID.log"
readonly -a QUERY_COMMAND=(
  "${PIR_BAZEL_COMMAND[@]}"
  "${PIR_BAZEL_STARTUP_FLAGS[@]}"
  query
  "${PIR_BAZEL_QUERY_FLAGS[@]}"
  "tests(//hintless_simplepir:all)"
)
readonly -a GTEST_LIST_COMMAND=(
  "${PIR_BAZEL_COMMAND[@]}"
  "${PIR_BAZEL_STARTUP_FLAGS[@]}"
  run
  "${PIR_BAZEL_ACTION_FLAGS[@]}"
  "$PIR_TARGET"
  --
  --gtest_list_tests
)

cd -- "$PIR_UPSTREAM_DIR"
{
  pir_print_context
  printf '\nBazel test targets:\n'
  pir_print_command "${QUERY_COMMAND[@]}"
  "${QUERY_COMMAND[@]}"
  printf '\nGoogleTest cases in %s:\n' "$PIR_TARGET"
  pir_print_command "${GTEST_LIST_COMMAND[@]}"
  "${GTEST_LIST_COMMAND[@]}"
} 2>&1 | tee "$LIST_LOG"

printf 'list_log=%s\n' "$LIST_LOG"

