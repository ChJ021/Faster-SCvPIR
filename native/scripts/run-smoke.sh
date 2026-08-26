#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

pir_verify_upstream
pir_prepare_compiler
pir_resolve_bazel
pir_require_command /usr/bin/time

readonly RUN_ID="$(pir_run_id)"
readonly RUN_LOG="$PIR_LOG_DIR/smoke-$RUN_ID.log"
readonly TIME_LOG="$PIR_LOG_DIR/smoke-$RUN_ID.time.txt"
readonly META_LOG="$PIR_LOG_DIR/smoke-$RUN_ID.metadata.txt"
readonly TEST_BINARY="$PIR_BAZEL_ROOT/symlinks/bazel-bin/hintless_simplepir/new_pir_test"
readonly -a BUILD_COMMAND=(
  "${PIR_BAZEL_COMMAND[@]}"
  "${PIR_BAZEL_STARTUP_FLAGS[@]}"
  build
  "${PIR_BAZEL_ACTION_FLAGS[@]}"
  "$PIR_TARGET"
)
readonly -a RUN_COMMAND=(
  "$TEST_BINARY"
  --gtest_filter=HintlessSimplePir.EndToEndPIRTest
)

cd -- "$PIR_UPSTREAM_DIR"
{
  pir_print_context
  printf '\nBuild/check configured binary:\n'
  pir_print_command "${BUILD_COMMAND[@]}"
  "${BUILD_COMMAND[@]}"
} 2>&1 | tee "$RUN_LOG"

[[ -x "$TEST_BINARY" ]] || pir_die "configured test binary is missing: $TEST_BINARY"

set +e
{
  printf '\nRun binary-only smoke test:\n'
  pir_print_command /usr/bin/time --verbose --output="$TIME_LOG" "${RUN_COMMAND[@]}"
  /usr/bin/time --verbose --output="$TIME_LOG" "${RUN_COMMAND[@]}"
} 2>&1 | tee -a "$RUN_LOG"
readonly -a PIPE_RESULTS=("${PIPESTATUS[@]}")
set -e

readonly RUN_STATUS="${PIPE_RESULTS[0]}"
readonly TEE_STATUS="${PIPE_RESULTS[1]}"
{
  printf 'run_id=%s\n' "$RUN_ID"
  printf 'finished_at=%s\n' "$(date --iso-8601=seconds)"
  printf 'profile=honest-h-smoke-2mib\n'
  printf 'target=%s\n' "$PIR_TARGET"
  printf 'upstream_commit=%s\n' "$PIR_UPSTREAM_COMMIT"
  printf 'measurement_scope=binary-only\n'
  printf 'highway_mode=%s\n' "$([[ "${PIR_SCALAR:-0}" == "1" ]] && printf scalar || printf native-dispatch)"
  printf 'binary=%s\n' "$TEST_BINARY"
  printf 'binary_sha256=%s\n' "$(sha256sum "$TEST_BINARY" | cut -d ' ' -f 1)"
  printf 'run_exit_code=%s\n' "$RUN_STATUS"
  printf 'tee_exit_code=%s\n' "$TEE_STATUS"
  printf 'run_log=%s\n' "$RUN_LOG"
  printf 'time_log=%s\n' "$TIME_LOG"
} >"$META_LOG"

printf 'run_log=%s\n' "$RUN_LOG"
printf 'time_log=%s\n' "$TIME_LOG"
printf 'metadata_log=%s\n' "$META_LOG"

if [[ "$TEE_STATUS" -ne 0 ]]; then
  pir_die "tee failed while capturing the smoke-test log (exit $TEE_STATUS)"
fi
if [[ "$RUN_STATUS" -ne 0 ]]; then
  pir_die "smoke test failed (exit $RUN_STATUS); inspect $RUN_LOG"
fi
