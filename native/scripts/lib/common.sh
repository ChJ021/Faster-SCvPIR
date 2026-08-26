#!/usr/bin/env bash

# Shared, pinned execution policy for the upstream Small-client vPIR PoC.

set -Eeuo pipefail

readonly PIR_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PIR_NATIVE_ROOT="$(cd -- "$PIR_LIB_DIR/../.." && pwd -P)"
readonly PIR_PROJECT_ROOT="$(cd -- "$PIR_NATIVE_ROOT/.." && pwd -P)"
readonly PIR_LOCK_FILE="$PIR_NATIVE_ROOT/manifests/upstream.lock.sh"

if [[ ! -f "$PIR_LOCK_FILE" ]]; then
  printf 'error: missing lock manifest: %s\n' "$PIR_LOCK_FILE" >&2
  exit 1
fi

# shellcheck source=../../manifests/upstream.lock.sh
source "$PIR_LOCK_FILE"
readonly PIR_UPSTREAM_URL PIR_UPSTREAM_COMMIT PIR_BAZEL_VERSION
readonly PIR_BAZEL_JOBS PIR_TARGET

readonly PIR_UPSTREAM_DIR="$PIR_NATIVE_ROOT/vendor/Verifiable-Hintless-PIR"
readonly PIR_EIGEN_DIR="$PIR_NATIVE_ROOT/vendor/eigen-3.4.0"
readonly PIR_EIGEN_ARCHIVE="$PIR_NATIVE_ROOT/toolchain/sources/eigen-3.4.0.zip"
readonly PIR_EIGEN_SHA256="eba3f3d414d2f8cba2919c78ec6daab08fc71ba2ba4ae502b7e5d4d99fc02cda"
readonly PIR_PATCHED_CLIENT_SHA256="2b24433a067a4747d3bcf210d16907a3c18eead802a05c0d8a59c69eb5b16b76"
readonly PIR_PATCHED_MAT_SHA256="2de69ab966fa322ade2bf92f405b21214ffa6e2def6d0728afdea61e453e946e"
readonly PIR_LOG_DIR="$PIR_NATIVE_ROOT/logs"
readonly PIR_BAZEL_ROOT="$PIR_NATIVE_ROOT/cache"
readonly PIR_OUTPUT_USER_ROOT="$PIR_BAZEL_ROOT/bazel-user"
readonly PIR_REPOSITORY_CACHE="$PIR_BAZEL_ROOT/repository"
readonly PIR_DISK_CACHE="$PIR_BAZEL_ROOT/disk"
readonly PIR_SYMLINK_PREFIX="$PIR_BAZEL_ROOT/symlinks/bazel-"

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

pir_verify_upstream() {
  pir_require_command git
  pir_require_command sha256sum
  [[ -d "$PIR_UPSTREAM_DIR" ]] || pir_die "upstream checkout is missing: $PIR_UPSTREAM_DIR"
  git -C "$PIR_UPSTREAM_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || pir_die "upstream path is not a Git worktree: $PIR_UPSTREAM_DIR"

  local actual_url actual_commit tracked_changes
  actual_url="$(git -C "$PIR_UPSTREAM_DIR" remote get-url origin)"
  actual_commit="$(git -C "$PIR_UPSTREAM_DIR" rev-parse HEAD)"
  tracked_changes="$(git -C "$PIR_UPSTREAM_DIR" status --porcelain=v1 --untracked-files=no)"

  [[ "$actual_url" == "$PIR_UPSTREAM_URL" ]] \
    || pir_die "origin mismatch: expected $PIR_UPSTREAM_URL, got $actual_url"
  [[ "$actual_commit" == "$PIR_UPSTREAM_COMMIT" ]] \
    || pir_die "commit mismatch: expected $PIR_UPSTREAM_COMMIT, got $actual_commit"
  local expected_tracked_changes
  expected_tracked_changes=$' M hintless_simplepir/client.cc\n M verisimplepir/src/lib/pir/mat.cpp'
  [[ "$tracked_changes" == "$expected_tracked_changes" ]] \
    || pir_die "upstream tracked changes do not match the two approved Clang 18 compatibility patches"
  local patched_client_digest patched_mat_digest
  patched_client_digest="$(sha256sum "$PIR_UPSTREAM_DIR/hintless_simplepir/client.cc")"
  patched_client_digest="${patched_client_digest%% *}"
  [[ "$patched_client_digest" == "$PIR_PATCHED_CLIENT_SHA256" ]] \
    || pir_die "patched client.cc checksum mismatch: expected $PIR_PATCHED_CLIENT_SHA256, got $patched_client_digest"
  patched_mat_digest="$(sha256sum "$PIR_UPSTREAM_DIR/verisimplepir/src/lib/pir/mat.cpp")"
  patched_mat_digest="${patched_mat_digest%% *}"
  [[ "$patched_mat_digest" == "$PIR_PATCHED_MAT_SHA256" ]] \
    || pir_die "patched mat.cpp checksum mismatch: expected $PIR_PATCHED_MAT_SHA256, got $patched_mat_digest"

  local test_source mode_header
  test_source="$PIR_UPSTREAM_DIR/hintless_simplepir/new_pir_test.cc"
  mode_header="$PIR_UPSTREAM_DIR/verisimplepir/src/lib/pir/utils.h"
  grep -Eq 'const int rows_db[[:space:]]*=[[:space:]]*2048;' "$test_source" \
    || pir_die "pinned 2 MiB smoke rows (2048) were not found"
  grep -Eq 'const int cols_db[[:space:]]*=[[:space:]]*1024;' "$test_source" \
    || pir_die "pinned 2 MiB smoke columns (1024) were not found"
  grep -Eq '^#define[[:space:]]+BSGS([[:space:]]|$)' "$mode_header" \
    || pir_die "BSGS must be enabled for the pinned smoke profile"
  if grep -Eq '^#define[[:space:]]+(FAKE_RUN|SH_RUN)([[:space:]]|$)' "$mode_header"; then
    pir_die "FAKE_RUN and SH_RUN must remain disabled for the honest-H verifiable smoke test"
  fi

  [[ -f "$PIR_EIGEN_ARCHIVE" ]] \
    || pir_die "pinned Eigen archive is missing: $PIR_EIGEN_ARCHIVE"
  [[ -f "$PIR_EIGEN_DIR/BUILD.bazel" && -f "$PIR_EIGEN_DIR/WORKSPACE.bazel" ]] \
    || pir_die "project-local Eigen Bazel repository is incomplete: $PIR_EIGEN_DIR"
  local eigen_archive_digest
  eigen_archive_digest="$(sha256sum "$PIR_EIGEN_ARCHIVE")"
  eigen_archive_digest="${eigen_archive_digest%% *}"
  [[ "$eigen_archive_digest" == "$PIR_EIGEN_SHA256" ]] \
    || pir_die "Eigen archive checksum mismatch: expected $PIR_EIGEN_SHA256, got $eigen_archive_digest"
}

pir_resolve_bazel() {
  pir_prepare_local_paths

  local candidate version_output
  local -a bazel_launcher=(env)
  if [[ -n "${BAZEL_BIN:-}" ]]; then
    candidate="$BAZEL_BIN"
  elif [[ -x "$PIR_NATIVE_ROOT/tools/bazel-$PIR_BAZEL_VERSION" ]]; then
    candidate="$PIR_NATIVE_ROOT/tools/bazel-$PIR_BAZEL_VERSION"
  elif [[ -x "$PIR_NATIVE_ROOT/tools/bazel-$PIR_BAZEL_VERSION-linux-x86_64" ]]; then
    candidate="$PIR_NATIVE_ROOT/tools/bazel-$PIR_BAZEL_VERSION-linux-x86_64"
  elif [[ -x "$PIR_NATIVE_ROOT/tools/bazelisk" ]]; then
    candidate="$PIR_NATIVE_ROOT/tools/bazelisk"
  else
    pir_die "project-local Bazel not found; install Bazel $PIR_BAZEL_VERSION under $PIR_NATIVE_ROOT/tools"
  fi

  [[ -x "$candidate" ]] || pir_die "Bazel is not executable: $candidate"
  if [[ "${PIR_KEEP_PROXY:-0}" != "1" ]]; then
    # This workspace is commonly opened with a stale localhost proxy. Let Bazel
    # fetch repositories directly unless the caller deliberately opts out.
    bazel_launcher+=(
      -u http_proxy -u https_proxy -u all_proxy
      -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY
    )
  fi
  if [[ "$(basename -- "$candidate")" == "bazelisk" ]]; then
    bazel_launcher+=("USE_BAZEL_VERSION=$PIR_BAZEL_VERSION")
  fi
  bazel_launcher+=("$candidate")
  PIR_BAZEL_COMMAND=("${bazel_launcher[@]}")

  PIR_BAZEL_STARTUP_FLAGS=(--batch "--output_user_root=$PIR_OUTPUT_USER_ROOT")
  version_output="$("${PIR_BAZEL_COMMAND[@]}" "${PIR_BAZEL_STARTUP_FLAGS[@]}" version 2>&1)" \
    || pir_die "could not execute project-local Bazel: $candidate"
  [[ "$version_output" == *"Build label: $PIR_BAZEL_VERSION"* ]] \
    || pir_die "Bazel version mismatch: expected $PIR_BAZEL_VERSION, got: $version_output"

  PIR_BAZEL_QUERY_FLAGS=(
    --noenable_bzlmod
    "--override_repository=com_gitlab_libeigen-eigen=$PIR_EIGEN_DIR"
    "--repository_cache=$PIR_REPOSITORY_CACHE"
    --color=no
    --curses=no
  )
  PIR_BAZEL_ACTION_FLAGS=(
    --noenable_bzlmod
    "--override_repository=com_gitlab_libeigen-eigen=$PIR_EIGEN_DIR"
    "--jobs=$PIR_BAZEL_JOBS"
    "--repository_cache=$PIR_REPOSITORY_CACHE"
    "--disk_cache=$PIR_DISK_CACHE"
    "--symlink_prefix=$PIR_SYMLINK_PREFIX"
    --color=no
    --curses=no
    -c opt
    --cxxopt=-std=c++17
    --cxxopt=-w
    --copt=-w
  )
  if [[ "${PIR_SCALAR:-0}" == "1" ]]; then
    PIR_BAZEL_ACTION_FLAGS+=(--cxxopt=-DHWY_COMPILE_ONLY_SCALAR=1)
  fi
}

pir_prepare_compiler() {
  export CC="${PIR_CC:-clang}"
  export CXX="${PIR_CXX:-clang++}"
  pir_require_command "$CC"
  pir_require_command "$CXX"
}

pir_run_id() {
  printf '%s-%s\n' "$(date -u '+%Y%m%dT%H%M%SZ')" "$$"
}

pir_print_command() {
  printf 'command:'
  printf ' %q' "$@"
  printf '\n'
}

pir_print_context() {
  printf 'project_root=%s\n' "$PIR_PROJECT_ROOT"
  printf 'upstream=%s\n' "$PIR_UPSTREAM_URL"
  printf 'commit=%s\n' "$PIR_UPSTREAM_COMMIT"
  printf 'target=%s\n' "$PIR_TARGET"
  printf 'profile=honest-h-smoke-2mib\n'
  printf 'bazel_version=%s\n' "$PIR_BAZEL_VERSION"
  printf 'bazel_jobs=%s\n' "$PIR_BAZEL_JOBS"
  printf 'bzlmod=false\n'
  printf 'eigen_override=%s\n' "$PIR_EIGEN_DIR"
  printf 'eigen_archive_sha256=%s\n' "$PIR_EIGEN_SHA256"
  printf 'patched_client_sha256=%s\n' "$PIR_PATCHED_CLIENT_SHA256"
  printf 'patched_mat_sha256=%s\n' "$PIR_PATCHED_MAT_SHA256"
  printf 'highway_mode=%s\n' "$([[ "${PIR_SCALAR:-0}" == "1" ]] && printf scalar || printf native-dispatch)"
  printf 'clear_inherited_proxy=%s\n' "$([[ "${PIR_KEEP_PROXY:-0}" == "1" ]] && printf false || printf true)"
  printf 'CC=%s\n' "$CC"
  printf 'CXX=%s\n' "$CXX"
}
