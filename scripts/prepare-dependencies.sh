#!/usr/bin/env bash

# Materialize the external Eigen Bazel repository from the pinned archive.
# The protocol source tree is committed at the project root and is not fetched
# or patched here.

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/toolchain.sh
source "$SCRIPT_DIR/lib/toolchain.sh"

pir_require_command sha256sum
pir_require_command unzip

[[ -f "$PIR_PROJECT_ROOT/WORKSPACE.bazel" ]] \
  || pir_die "Bazel workspace is missing: $PIR_PROJECT_ROOT/WORKSPACE.bazel"
[[ -f "$PIR_PROJECT_ROOT/bazel/eigen.bzl" ]] \
  || pir_die "Eigen build definition is missing: $PIR_PROJECT_ROOT/bazel/eigen.bzl"

eigen_archive_sha256="$(file_sha256 "$PIR_EIGEN_ARCHIVE")"
[[ "$eigen_archive_sha256" == "$PIR_EIGEN_SHA256" ]] \
  || pir_die "Eigen archive checksum mismatch: expected $PIR_EIGEN_SHA256, got $eigen_archive_sha256"
if [[ ! -d "$PIR_EIGEN_DIR" ]]; then
  [[ ! -e "$PIR_EIGEN_DIR" ]] \
    || pir_die "Eigen destination exists but is incomplete: $PIR_EIGEN_DIR"
  mkdir -p "$PIR_PROJECT_ROOT/vendor"
  unzip -q "$PIR_EIGEN_ARCHIVE" -d "$PIR_PROJECT_ROOT/vendor"
fi

# The upstream archive is plain Eigen source; Bazel needs a repository marker
# and a BUILD file. Reuse the build definition shipped with the workspace
# instead of committing generated files.
if [[ ! -f "$PIR_EIGEN_DIR/BUILD.bazel" ]]; then
  install -m 0644 "$PIR_PROJECT_ROOT/bazel/eigen.bzl" "$PIR_EIGEN_DIR/BUILD.bazel"
fi
if [[ ! -f "$PIR_EIGEN_DIR/WORKSPACE.bazel" ]]; then
  printf 'workspace(name = "com_gitlab_libeigen_eigen_local")\n' \
    > "$PIR_EIGEN_DIR/WORKSPACE.bazel"
fi

pir_prepare_local_paths
pir_prepare_compiler
pir_resolve_bazel

printf 'upstream_commit=%s\n' "$PIR_UPSTREAM_COMMIT"
printf 'workspace=%s\n' "$PIR_PROJECT_ROOT"
printf 'eigen_sha256=%s\n' "$PIR_EIGEN_SHA256"
printf 'status=ready\n'
