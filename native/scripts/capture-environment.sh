#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

pir_verify_upstream
pir_prepare_compiler
pir_resolve_bazel
pir_require_command lscpu
pir_require_command dpkg-query

readonly RUN_ID="$(pir_run_id)"
readonly ENV_LOG="$PIR_NATIVE_ROOT/manifests/environment-$RUN_ID.txt"
readonly TEST_BINARY="$PIR_BAZEL_ROOT/symlinks/bazel-bin/hintless_simplepir/new_pir_test"

{
  printf 'schema=small-client-vpir-native-environment-v1\n'
  printf 'captured_at_utc=%s\n' "$(date -u --iso-8601=seconds)"
  pir_print_context
  printf 'uname=%s\n' "$(uname -a)"
  printf 'os_release=%s\n' "$(. /etc/os-release && printf '%s %s' "$NAME" "$VERSION_ID")"
  printf 'cpu_architecture=%s\n' "$(lscpu | awk -F: '/^Architecture:/ {gsub(/^[[:space:]]+/, "", $2); print $2}')"
  printf 'cpu_model=%s\n' "$(lscpu | awk -F: '/^Model name:/ {gsub(/^[[:space:]]+/, "", $2); print $2}')"
  printf 'logical_cpus=%s\n' "$(nproc)"
  printf 'memory_bytes=%s\n' "$(awk '/^MemTotal:/ {print $2 * 1024}' /proc/meminfo)"
  printf 'clang=%s\n' "$(clang++ --version | sed -n '1p')"
  printf 'bazel=%s\n' "$("${PIR_BAZEL_COMMAND[@]}" "${PIR_BAZEL_STARTUP_FLAGS[@]}" version | awk -F': ' '/^Build label:/ {print $2}')"
  printf 'openssl=%s\n' "$(openssl version)"
  printf 'upstream_status=%s\n' "$(git -C "$PIR_UPSTREAM_DIR" status --porcelain=v1 --untracked-files=no | tr '\n' ';')"
  printf 'bazel_sha256=%s\n' "$(sha256sum "$PIR_NATIVE_ROOT/tools/bazel-$PIR_BAZEL_VERSION" | cut -d ' ' -f 1)"
  if [[ -x "$TEST_BINARY" ]]; then
    printf 'binary_sha256=%s\n' "$(sha256sum "$TEST_BINARY" | cut -d ' ' -f 1)"
  else
    printf 'binary_sha256=not-built\n'
  fi
  dpkg-query -W -f='package=${Package}\tversion=${Version}\n' \
    clang libssl-dev libgsl-dev libgslcblas0 libmsgsl-dev pkg-config gdb
} | tee "$ENV_LOG"

printf 'environment_log=%s\n' "$ENV_LOG"
