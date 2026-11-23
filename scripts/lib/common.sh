#!/usr/bin/env bash

# Shared paths and helpers for the paper-v1 experiment tooling.
# Feature-specific helpers live in sibling modules: toolchain.sh,
# manifest.sh, checks.sh, report.sh and cell.sh.

set -Eeuo pipefail

readonly PIR_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PIR_PROJECT_ROOT="$(cd -- "$PIR_LIB_DIR/../.." && pwd -P)"
readonly PIR_LOCK_FILE="$PIR_PROJECT_ROOT/manifests/upstream.lock.sh"

if [[ ! -f "$PIR_LOCK_FILE" ]]; then
  printf 'error: missing lock manifest: %s\n' "$PIR_LOCK_FILE" >&2
  exit 1
fi

# shellcheck source=../../manifests/upstream.lock.sh
source "$PIR_LOCK_FILE"
readonly PIR_UPSTREAM_URL PIR_UPSTREAM_COMMIT PIR_BAZEL_VERSION
readonly PIR_BAZEL_JOBS PIR_TARGET

readonly PIR_TEST_SOURCE="$PIR_PROJECT_ROOT/hintless_simplepir/pir_experiment.cc"
readonly PIR_MANIFEST="$PIR_PROJECT_ROOT/manifests/paper-v1.json"
readonly PIR_MANIFEST_CHECKSUM="$PIR_PROJECT_ROOT/manifests/paper-v1.sha256"
readonly PIR_CONFIG_HELPER="$PIR_PROJECT_ROOT/experiments/paper_config.py"
readonly PIR_EIGEN_DIR="$PIR_PROJECT_ROOT/vendor/eigen-3.4.0"
readonly PIR_EIGEN_ARCHIVE="$PIR_PROJECT_ROOT/toolchain/sources/eigen-3.4.0.zip"
readonly PIR_EIGEN_SHA256="eba3f3d414d2f8cba2919c78ec6daab08fc71ba2ba4ae502b7e5d4d99fc02cda"
readonly PIR_LOG_DIR="$PIR_PROJECT_ROOT/logs"
readonly PIR_BAZEL_ROOT="$PIR_PROJECT_ROOT/cache"
readonly PIR_OUTPUT_USER_ROOT="$PIR_BAZEL_ROOT/bazel-user"
readonly PIR_REPOSITORY_CACHE="$PIR_BAZEL_ROOT/repository"
readonly PIR_DISK_CACHE="$PIR_BAZEL_ROOT/disk"
readonly PIR_SYMLINK_PREFIX="$PIR_BAZEL_ROOT/symlinks/bazel-"
readonly PIR_TEST_BINARY="$PIR_BAZEL_ROOT/symlinks/bazel-bin/hintless_simplepir/pir_experiment"

declare -ag PIR_BAZEL_COMMAND=()
declare -ag PIR_BAZEL_STARTUP_FLAGS=()
declare -ag PIR_BAZEL_QUERY_FLAGS=()
declare -ag PIR_BAZEL_ACTION_FLAGS=()

pir_die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

pir_require_command() {
  command -v "$1" >/dev/null 2>&1 || pir_die "required command not found: $1"
}

pir_prepare_local_paths() {
  mkdir -p \
    "$PIR_LOG_DIR" \
    "$PIR_OUTPUT_USER_ROOT" \
    "$PIR_REPOSITORY_CACHE" \
    "$PIR_DISK_CACHE" \
    "$(dirname -- "$PIR_SYMLINK_PREFIX")"
}

pir_run_id() {
  printf '%s-%s\n' "$(date -u '+%Y%m%dT%H%M%SZ')" "$$"
}

pir_print_command() {
  printf 'command:'
  printf ' %q' "$@"
  printf '\n'
}

file_sha256() {
  local digest
  digest="$(sha256sum "$1")"
  printf '%s\n' "${digest%% *}"
}

pir_print_context() {
  printf 'project_root=%s\n' "$PIR_PROJECT_ROOT"
  printf 'upstream=%s\n' "$PIR_UPSTREAM_URL"
  printf 'commit=%s\n' "$PIR_UPSTREAM_COMMIT"
  printf 'target=%s\n' "$PIR_TARGET"
  printf 'bazel_version=%s\n' "$PIR_BAZEL_VERSION"
  printf 'bazel_jobs=%s\n' "$PIR_BAZEL_JOBS"
  printf 'bzlmod=false\n'
  printf 'eigen_override=%s\n' "$PIR_EIGEN_DIR"
  printf 'eigen_archive_sha256=%s\n' "$PIR_EIGEN_SHA256"
  printf 'highway_mode=%s\n' "$([[ "${PIR_SCALAR:-0}" == "1" ]] && printf scalar || printf native-dispatch)"
  printf 'clear_inherited_proxy=%s\n' "$([[ "${PIR_KEEP_PROXY:-0}" == "1" ]] && printf false || printf true)"
  printf 'CC=%s\n' "$CC"
  printf 'CXX=%s\n' "$CXX"
}
