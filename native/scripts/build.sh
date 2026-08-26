#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

pir_verify_upstream
pir_prepare_compiler
pir_resolve_bazel

readonly RUN_ID="$(pir_run_id)"
readonly BUILD_LOG="$PIR_LOG_DIR/build-$RUN_ID.log"
readonly -a BUILD_COMMAND=(
  "${PIR_BAZEL_COMMAND[@]}"
  "${PIR_BAZEL_STARTUP_FLAGS[@]}"
  build
  "${PIR_BAZEL_ACTION_FLAGS[@]}"
  --verbose_failures
  "$PIR_TARGET"
)

cd -- "$PIR_UPSTREAM_DIR"
{
  pir_print_context
  pir_print_command "${BUILD_COMMAND[@]}"
  "${BUILD_COMMAND[@]}"
} 2>&1 | tee "$BUILD_LOG"

printf 'build_log=%s\n' "$BUILD_LOG"

