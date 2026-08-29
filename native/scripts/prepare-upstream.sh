#!/usr/bin/env bash

# Recreate the patched upstream source tree without publishing a vendored copy.

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly SOURCE_PATCH="$PIR_NATIVE_ROOT/patches/ypir-ntt-preprocessing.patch"
readonly SOURCE_PATCH_SHA256="3af8621d1c5ec67ee2e2b50946dcd91be821848255f2cd935001e2ffd87ab657"

pir_require_command git
pir_require_command sha256sum
pir_require_command unzip

[[ -f "$SOURCE_PATCH" ]] || pir_die "source patch is missing: $SOURCE_PATCH"
actual_patch_sha256="$(sha256sum "$SOURCE_PATCH")"
actual_patch_sha256="${actual_patch_sha256%% *}"
[[ "$actual_patch_sha256" == "$SOURCE_PATCH_SHA256" ]] \
  || pir_die "source patch checksum mismatch: expected $SOURCE_PATCH_SHA256, got $actual_patch_sha256"

mkdir -p "$PIR_NATIVE_ROOT/vendor"
if [[ ! -d "$PIR_UPSTREAM_DIR/.git" ]]; then
  [[ ! -e "$PIR_UPSTREAM_DIR" ]] \
    || pir_die "upstream path exists but is not a Git checkout: $PIR_UPSTREAM_DIR"
  git clone --no-checkout "$PIR_UPSTREAM_URL" "$PIR_UPSTREAM_DIR"
  git -C "$PIR_UPSTREAM_DIR" checkout --detach "$PIR_UPSTREAM_COMMIT"
fi

actual_url="$(git -C "$PIR_UPSTREAM_DIR" remote get-url origin)"
actual_commit="$(git -C "$PIR_UPSTREAM_DIR" rev-parse HEAD)"
[[ "$actual_url" == "$PIR_UPSTREAM_URL" ]] \
  || pir_die "origin mismatch: expected $PIR_UPSTREAM_URL, got $actual_url"
[[ "$actual_commit" == "$PIR_UPSTREAM_COMMIT" ]] \
  || pir_die "commit mismatch: expected $PIR_UPSTREAM_COMMIT, got $actual_commit"

if git -C "$PIR_UPSTREAM_DIR" apply --reverse --check "$SOURCE_PATCH" >/dev/null 2>&1; then
  patch_state="already-applied"
else
  [[ -z "$(git -C "$PIR_UPSTREAM_DIR" status --porcelain=v1 --untracked-files=all)" ]] \
    || pir_die "upstream checkout is dirty and does not exactly contain the project patch"
  git -C "$PIR_UPSTREAM_DIR" apply --check "$SOURCE_PATCH"
  git -C "$PIR_UPSTREAM_DIR" apply "$SOURCE_PATCH"
  patch_state="applied"
fi
git -C "$PIR_UPSTREAM_DIR" diff --check

eigen_archive_sha256="$(sha256sum "$PIR_EIGEN_ARCHIVE")"
eigen_archive_sha256="${eigen_archive_sha256%% *}"
[[ "$eigen_archive_sha256" == "$PIR_EIGEN_SHA256" ]] \
  || pir_die "Eigen archive checksum mismatch: expected $PIR_EIGEN_SHA256, got $eigen_archive_sha256"
if [[ ! -f "$PIR_EIGEN_DIR/BUILD.bazel" || ! -f "$PIR_EIGEN_DIR/WORKSPACE.bazel" ]]; then
  [[ ! -e "$PIR_EIGEN_DIR" ]] \
    || pir_die "Eigen destination exists but is incomplete: $PIR_EIGEN_DIR"
  unzip -q "$PIR_EIGEN_ARCHIVE" -d "$PIR_NATIVE_ROOT/vendor"
fi

printf 'upstream_commit=%s\n' "$actual_commit"
printf 'source_patch_sha256=%s\n' "$SOURCE_PATCH_SHA256"
printf 'source_patch_state=%s\n' "$patch_state"
printf 'eigen_sha256=%s\n' "$PIR_EIGEN_SHA256"
printf 'status=ready\n'
