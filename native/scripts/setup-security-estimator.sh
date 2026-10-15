#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly NATIVE_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly LOCK_FILE="$NATIVE_ROOT/security/estimator.lock.sh"
readonly CACHE_ROOT="$NATIVE_ROOT/cache/security"
readonly ARCHIVE_ROOT="$CACHE_ROOT/archives"
readonly SOURCE_ROOT="$CACHE_ROOT/sources"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

[[ -f "$LOCK_FILE" ]] || die "missing estimator lock: $LOCK_FILE"
# shellcheck source=../security/estimator.lock.sh
source "$LOCK_FILE"

require_command curl
require_command sage
require_command sha256sum
require_command tar

sage --version | grep -Eq '^SageMath version 9\.5([,[:space:]]|$)' \
  || die "this deployment is calibrated for SageMath 9.5"

mkdir -p "$ARCHIVE_ROOT" "$SOURCE_ROOT"

prepare_snapshot() {
  local label="$1"
  local commit="$2"
  local expected_sha256="$3"
  local archive="$ARCHIVE_ROOT/lattice-estimator-$commit.tar.gz"
  local destination="$SOURCE_ROOT/lattice-estimator-$commit"
  local actual_sha256 temporary

  if [[ ! -f "$archive" ]]; then
    printf 'fetching_estimator=%s commit=%s\n' "$label" "$commit"
    curl --noproxy '*' -fsSL "$SECURITY_ESTIMATOR_URL/$commit" -o "$archive"
  fi

  actual_sha256="$(sha256sum "$archive")"
  actual_sha256="${actual_sha256%% *}"
  [[ "$actual_sha256" == "$expected_sha256" ]] \
    || die "$label archive hash mismatch: expected $expected_sha256, got $actual_sha256"

  if [[ ! -f "$destination/estimator/__init__.py" ]]; then
    temporary="$(mktemp -d "$SOURCE_ROOT/.extract-$commit-XXXXXX")"
    trap 'rm -rf -- "$temporary"' RETURN
    tar -xzf "$archive" --strip-components=1 -C "$temporary"
    [[ -f "$temporary/estimator/__init__.py" ]] \
      || die "$label archive does not contain estimator/__init__.py"
    printf '%s\n' "$expected_sha256" >"$temporary/.archive-sha256"
    mv -- "$temporary" "$destination"
    trap - RETURN
  fi

  [[ -f "$destination/.archive-sha256" ]] \
    || die "$label snapshot is missing its integrity marker; move it aside and rerun setup"
  [[ "$(<"$destination/.archive-sha256")" == "$expected_sha256" ]] \
    || die "$label snapshot integrity marker does not match the lock file"

  printf 'estimator_ready=%s commit=%s sha256=%s\n' \
    "$label" "$commit" "$actual_sha256"
}

prepare_snapshot small-client "$SMALL_CLIENT_ESTIMATOR_COMMIT" \
  "$SMALL_CLIENT_ESTIMATOR_SHA256"
prepare_snapshot ypir "$YPIR_ESTIMATOR_COMMIT" \
  "$YPIR_ESTIMATOR_SHA256"
