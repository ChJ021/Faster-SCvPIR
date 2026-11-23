#!/usr/bin/env bash

# Native compiler and Bazel discovery.

pir_prepare_compiler() {
  export CC="${PIR_CC:-clang}"
  export CXX="${PIR_CXX:-clang++}"
  pir_require_command "$CC"
  pir_require_command "$CXX"
}

pir_resolve_bazel() {
  pir_prepare_local_paths

  local candidate version_output
  local -a bazel_launcher=(env)
  if [[ -n "${BAZEL_BIN:-}" ]]; then
    candidate="$BAZEL_BIN"
  elif [[ -x "$PIR_PROJECT_ROOT/tools/bazel-$PIR_BAZEL_VERSION" ]]; then
    candidate="$PIR_PROJECT_ROOT/tools/bazel-$PIR_BAZEL_VERSION"
  else
    pir_die "project-local Bazel not found; install Bazel $PIR_BAZEL_VERSION under $PIR_PROJECT_ROOT/tools"
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
