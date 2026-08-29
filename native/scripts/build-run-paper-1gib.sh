#!/usr/bin/env bash

# Prepare, build, and run the author's 1 GiB honest-H paper profile in place.
#
# This script intentionally does not call pir_verify_upstream after changing the
# profile: that verifier is the immutable 2 MiB baseline gate.  Instead, this
# file enforces the pinned upstream commit, local toolchain invariants, required
# module sources, and a clean patch shape via `git diff --check`.

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly PAPER_PROFILE="honest-h-paper-1gib"
readonly TEST_SOURCE="$PIR_UPSTREAM_DIR/hintless_simplepir/new_pir_test.cc"
readonly MINIMUM_MEMORY_KIB=$((20 * 1024 * 1024))
readonly RECOMMENDED_MEMORY_KIB=$((32 * 1024 * 1024))

usage() {
  cat <<'EOF'
Usage: native/scripts/build-run-paper-1gib.sh [OPTIONS]

Prepare the current upstream checkout in place for the author's 1 GiB
honest-H profile, build it with the pinned project-local Bazel toolchain, and
run HintlessSimplePir.EndToEndPIRTest while recording resource usage.

Options:
  --preproc-profile=baseline         Dense main and dense offline preprocessors.
  --preproc-profile=ypir-main        Exact-NTT main, dense offline preprocessor.
  --preproc-profile=distpir-offline  Dense main, exact-NTT H_2 preprocessor.
  --preproc-profile=hybrid           Exact-NTT main and H_2 preprocessors.
  --offline-ring-degree=2048|4096    H_2 ring degree (default: 4096; only
                                     distpir-offline and hybrid).
  --prepare-only  Validate and change the three profile constants, then stop.
  --build-only    Prepare and build, but do not run the memory-intensive test.
  -h, --help      Show this help text.

Environment:
  PIR_ALLOW_LOW_MEMORY=1  Override the <20 GiB runtime refusal.
  PIR_KEEP_PROXY=1        Preserve caller HTTP(S)/ALL proxy variables.
  PIR_SCALAR=1            Compile Highway in scalar fallback mode.

The operation is idempotent. The source is prepared for the 1 GiB database
once; backend selection is a runtime argument and never rewrites source or a
compile-time macro. Existing logs remain under native/logs; new artifacts go
under native/logs/1gib/<preproc-profile>/<run-id>/.
EOF
}

mode="all"
preproc_profile="baseline"
offline_ring_degree="4096"
offline_ring_degree_explicit="0"
for option in "$@"; do
  case "$option" in
    --preproc-profile=baseline)
      preproc_profile="baseline"
      ;;
    --preproc-profile=ypir-main)
      preproc_profile="ypir-main"
      ;;
    --preproc-profile=distpir-offline)
      preproc_profile="distpir-offline"
      ;;
    --preproc-profile=hybrid)
      preproc_profile="hybrid"
      ;;
    --offline-ring-degree=2048 | --offline-ring-degree=4096)
      offline_ring_degree="${option#*=}"
      offline_ring_degree_explicit="1"
      ;;
    --offline-ring-degree=*)
      pir_die "offline ring degree must be 2048 or 4096"
      ;;
    --prepare-only | --build-only)
      [[ "$mode" == "all" ]] || pir_die "select at most one execution mode"
      mode="$option"
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      pir_die "unsupported option: $option"
      ;;
  esac
done
readonly MODE="$mode"
readonly PREPROC_PROFILE="$preproc_profile"
readonly OFFLINE_RING_DEGREE_REQUESTED="$offline_ring_degree"
readonly OFFLINE_RING_DEGREE_EXPLICIT="$offline_ring_degree_explicit"

if [[ "$PREPROC_PROFILE" == "ypir-main" || "$PREPROC_PROFILE" == "hybrid" ]]; then
  readonly MAIN_PREPROC_BACKEND="ypir-exact-ntt"
  readonly MAIN_RING_DEGREE="2048"
  readonly MAIN_PAD_BLOCK_COUNT="16"
  readonly MAIN_STRUCTURED_PAD_VERSION="1"
  readonly MAIN_PRG_DOMAIN="small-client-pir/main-pad/ypir-ntt/v1"
  readonly MAIN_SECURITY_STATUS="experimental-ring-lwe-ring-sis-parameters-not-audited"
else
  readonly MAIN_PREPROC_BACKEND="dense-lwe"
  readonly MAIN_RING_DEGREE="0"
  readonly MAIN_PAD_BLOCK_COUNT="0"
  readonly MAIN_STRUCTURED_PAD_VERSION="0"
  readonly MAIN_PRG_DOMAIN="small-client-pir/main-pad/dense-lwe/legacy"
  readonly MAIN_SECURITY_STATUS="baseline-lwe"
fi
if [[ "$PREPROC_PROFILE" == "distpir-offline" || "$PREPROC_PROFILE" == "hybrid" ]]; then
  readonly OFFLINE_PREPROC_BACKEND="ypir-offline-exact-ntt"
  readonly OFFLINE_RING_DEGREE="$OFFLINE_RING_DEGREE_REQUESTED"
  readonly OFFLINE_PAD_BLOCK_COUNT="$((32768 / OFFLINE_RING_DEGREE_REQUESTED))"
  readonly OFFLINE_STRUCTURED_PAD_VERSION="1"
  readonly OFFLINE_PRG_DOMAIN="small-client-pir/offline-pad/ypir-ntt/v1"
  readonly OFFLINE_SECURITY_STATUS="experimental-ring-lwe-parameters-not-audited"
else
  [[ "$OFFLINE_RING_DEGREE_EXPLICIT" == "0" ]] \
    || pir_die "--offline-ring-degree is only valid for distpir-offline and hybrid"
  readonly OFFLINE_PREPROC_BACKEND="dense-offline"
  readonly OFFLINE_RING_DEGREE="0"
  readonly OFFLINE_PAD_BLOCK_COUNT="0"
  readonly OFFLINE_STRUCTURED_PAD_VERSION="0"
  readonly OFFLINE_PRG_DOMAIN="legacy-process-rng-no-domain-separation"
  readonly OFFLINE_SECURITY_STATUS="baseline-lwe"
fi
readonly OFFLINE_MODULUS="18014398492704769"

pir_require_command git
pir_require_command sha256sum
pir_require_command sed
pir_require_command grep
pir_require_command tee
pir_require_command flock
pir_require_command readlink
pir_require_command /usr/bin/time

[[ "$(uname -m)" == "x86_64" ]] \
  || pir_die "the bundled Bazel binary and validated native profile require x86_64"

pir_prepare_local_paths
readonly PROFILE_LOG_ROOT="$PIR_LOG_DIR/1gib/$PREPROC_PROFILE"
mkdir -p "$PROFILE_LOG_ROOT"

# Prevent two copies of this orchestration script from allocating the paper
# profile concurrently.  Manual binary launches are checked again before run.
exec 9>"$PROFILE_LOG_ROOT/.execution.lock"
flock -n 9 || pir_die "another 1 GiB build/run script already holds the execution lock"

readonly WORKSPACE_TEST_BINARY="$PIR_BAZEL_ROOT/symlinks/bazel-bin/hintless_simplepir/new_pir_test"
ensure_no_active_test() {
  [[ -e "$WORKSPACE_TEST_BINARY" ]] || return 0

  local expected_executable process_exe process_executable
  expected_executable="$(readlink -e -- "$WORKSPACE_TEST_BINARY")" \
    || pir_die "could not resolve the existing workspace test binary"
  for process_exe in /proc/[0-9]*/exe; do
    process_executable="$(readlink -e -- "$process_exe" 2>/dev/null || true)"
    if [[ -n "$process_executable" && "$process_executable" == "$expected_executable" ]]; then
      pir_die "a new_pir_test process using this workspace binary is already running"
    fi
  done
}
ensure_no_active_test

file_sha256() {
  local digest
  digest="$(sha256sum "$1")"
  printf '%s\n' "${digest%% *}"
}

verify_common_checkout() {
  [[ -d "$PIR_UPSTREAM_DIR/.git" ]] \
    || pir_die "upstream Git metadata is missing: $PIR_UPSTREAM_DIR/.git"

  local actual_url actual_commit eigen_digest
  actual_url="$(git -C "$PIR_UPSTREAM_DIR" remote get-url origin)"
  actual_commit="$(git -C "$PIR_UPSTREAM_DIR" rev-parse HEAD)"
  [[ "$actual_url" == "$PIR_UPSTREAM_URL" ]] \
    || pir_die "origin mismatch: expected $PIR_UPSTREAM_URL, got $actual_url"
  [[ "$actual_commit" == "$PIR_UPSTREAM_COMMIT" ]] \
    || pir_die "commit mismatch: expected $PIR_UPSTREAM_COMMIT, got $actual_commit"

  [[ -f "$PIR_EIGEN_ARCHIVE" ]] \
    || pir_die "pinned Eigen archive is missing: $PIR_EIGEN_ARCHIVE"
  [[ -f "$PIR_EIGEN_DIR/BUILD.bazel" && -f "$PIR_EIGEN_DIR/WORKSPACE.bazel" ]] \
    || pir_die "project-local Eigen Bazel repository is incomplete"
  eigen_digest="$(file_sha256 "$PIR_EIGEN_ARCHIVE")"
  [[ "$eigen_digest" == "$PIR_EIGEN_SHA256" ]] \
    || pir_die "pinned Eigen archive checksum mismatch"

  local mode_header
  mode_header="$PIR_UPSTREAM_DIR/verisimplepir/src/lib/pir/utils.h"
  grep -Eq '^#define[[:space:]]+BSGS([[:space:]]|$)' "$mode_header" \
    || pir_die "BSGS must be enabled for the paper profile"
  if grep -Eq '^#define[[:space:]]+(FAKE_RUN|SH_RUN)([[:space:]]|$)' "$mode_header"; then
    pir_die "FAKE_RUN and SH_RUN must remain disabled"
  fi

  [[ -f "$PIR_UPSTREAM_DIR/hintless_simplepir/main_preprocessor.cc" \
     && -f "$PIR_UPSTREAM_DIR/hintless_simplepir/offline_preprocessor.cc" \
     && -f "$PIR_UPSTREAM_DIR/lwe/negacyclic_ntt.cc" ]] \
    || pir_die "structured preprocessing module files are missing"
  grep -Fq -- '--preproc-profile=' "$TEST_SOURCE" \
    || pir_die "runtime preprocessor profile parser is missing"
  git -C "$PIR_UPSTREAM_DIR" diff --check
}

verify_1_source() {
  grep -Eq 'const int rows_db[[:space:]]*=[[:space:]]*32768;' "$TEST_SOURCE" \
    || pir_die "paper profile rows_db=32768 is missing"
  grep -Eq 'const int cols_db[[:space:]]*=[[:space:]]*32768;' "$TEST_SOURCE" \
    || pir_die "paper profile cols_db=32768 is missing"
  grep -Eq '^[[:space:]]*\.db_stack_cells[[:space:]]*=[[:space:]]*1,' "$TEST_SOURCE" \
    || pir_die "paper profile db_stack_cells=1 is missing"
  grep -Eq '^[[:space:]]*\.db_record_bit_size[[:space:]]*=[[:space:]]*8,' "$TEST_SOURCE" \
    || pir_die "paper profile db_record_bit_size=8 is missing"
  grep -Eq '^bool use_static_db[[:space:]]*=[[:space:]]*true;' "$TEST_SOURCE" \
    || pir_die "paper profile requires the static database path"
}

prepare_1_source() {
  verify_common_checkout

  if grep -Eq 'const int rows_db[[:space:]]*=[[:space:]]*2048;' "$TEST_SOURCE" \
      && grep -Eq 'const int cols_db[[:space:]]*=[[:space:]]*1024;' "$TEST_SOURCE" \
      && grep -Eq '^[[:space:]]*\.db_stack_cells[[:space:]]*=[[:space:]]*1,' "$TEST_SOURCE"; then
    sed -i -E \
      -e 's/^const int rows_db[[:space:]]*=[[:space:]]*2048;$/const int rows_db = 32768;/' \
      -e 's/^const int cols_db[[:space:]]*=[[:space:]]*1024;$/const int cols_db = 32768;/' \
      -e 's/^[[:space:]]*\.db_stack_cells[[:space:]]*=[[:space:]]*1,$/    .db_stack_cells = 1,/' \
      "$TEST_SOURCE"
  elif grep -Eq 'const int rows_db[[:space:]]*=[[:space:]]*32768;' "$TEST_SOURCE" \
      && grep -Eq 'const int cols_db[[:space:]]*=[[:space:]]*32768;' "$TEST_SOURCE" \
      && grep -Eq '^[[:space:]]*\.db_stack_cells[[:space:]]*=[[:space:]]*1,' "$TEST_SOURCE"; then
    printf 'profile_source=already-prepared\n'
  elif grep -Eq 'const int rows_db[[:space:]]*=[[:space:]]*32768;' "$TEST_SOURCE" \
      && grep -Eq 'const int cols_db[[:space:]]*=[[:space:]]*16384;' "$TEST_SOURCE" \
      && grep -Eq '^[[:space:]]*\.db_stack_cells[[:space:]]*=[[:space:]]*8,' "$TEST_SOURCE"; then
    sed -i -E \
      -e 's/^const int cols_db[[:space:]]*=[[:space:]]*16384;$/const int cols_db = 32768;/' \
      -e 's/^[[:space:]]*\.db_stack_cells[[:space:]]*=[[:space:]]*8,$/    .db_stack_cells = 1,/' \
      "$TEST_SOURCE"
  else
    pir_die "new_pir_test.cc has none of the supported 2 MiB, 512 MiB, or 1 GiB database constants"
  fi

  verify_1_source
}

effective_available_memory_kib() {
  local available_kib cgroup_limit_bytes cgroup_used_bytes cgroup_available_kib
  available_kib="$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo)"
  [[ "$available_kib" =~ ^[0-9]+$ ]] \
    || pir_die "could not read MemAvailable from /proc/meminfo"

  # cgroup v2: bound host MemAvailable by the memory still available to this
  # cgroup. Swap is deliberately excluded from the RAM safety gate.
  if [[ -r /sys/fs/cgroup/memory.max && -r /sys/fs/cgroup/memory.current ]]; then
    cgroup_limit_bytes="$(< /sys/fs/cgroup/memory.max)"
    cgroup_used_bytes="$(< /sys/fs/cgroup/memory.current)"
    if [[ "$cgroup_limit_bytes" =~ ^[0-9]+$ && "$cgroup_used_bytes" =~ ^[0-9]+$ ]]; then
      if ((cgroup_used_bytes >= cgroup_limit_bytes)); then
        cgroup_available_kib=0
      else
        cgroup_available_kib=$(((cgroup_limit_bytes - cgroup_used_bytes) / 1024))
      fi
      if ((cgroup_available_kib < available_kib)); then
        available_kib="$cgroup_available_kib"
      fi
    fi
  # cgroup v1 compatibility.
  elif [[ -r /sys/fs/cgroup/memory/memory.limit_in_bytes \
       && -r /sys/fs/cgroup/memory/memory.usage_in_bytes ]]; then
    cgroup_limit_bytes="$(< /sys/fs/cgroup/memory/memory.limit_in_bytes)"
    cgroup_used_bytes="$(< /sys/fs/cgroup/memory/memory.usage_in_bytes)"
    if [[ "$cgroup_limit_bytes" =~ ^[0-9]+$ && "$cgroup_used_bytes" =~ ^[0-9]+$ ]]; then
      if ((cgroup_used_bytes >= cgroup_limit_bytes)); then
        cgroup_available_kib=0
      else
        cgroup_available_kib=$(((cgroup_limit_bytes - cgroup_used_bytes) / 1024))
      fi
      if ((cgroup_available_kib < available_kib)); then
        available_kib="$cgroup_available_kib"
      fi
    fi
  fi
  printf '%s\n' "$available_kib"
}

check_runtime_memory() {
  local memory_kib
  memory_kib="$(effective_available_memory_kib)"
  printf 'effective_available_memory_kib=%s\n' "$memory_kib"
  if ((memory_kib < MINIMUM_MEMORY_KIB)); then
    if [[ "${PIR_ALLOW_LOW_MEMORY:-0}" != "1" ]]; then
      pir_die "effective memory is below 20 GiB; set PIR_ALLOW_LOW_MEMORY=1 only for an intentional swap/OOM-risk experiment"
    fi
    printf 'warning: low-memory override enabled; the 1 GiB run may swap heavily or be OOM-killed\n' >&2
  elif ((memory_kib < RECOMMENDED_MEMORY_KIB)); then
    printf 'warning: less than the recommended 32 GiB is available to this process\n' >&2
  fi
}

write_context() {
  local output_file="$1"
  {
    printf 'schema=small-client-vpir-paper-1gib-context-v2\n'
    printf 'captured_at=%s\n' "$(date --iso-8601=seconds)"
    printf 'project_root=%s\n' "$PIR_PROJECT_ROOT"
    printf 'paper_profile=%s\n' "$PAPER_PROFILE"
    printf 'preproc_profile=%s\n' "$PREPROC_PROFILE"
    printf 'main_preproc_backend=%s\n' "$MAIN_PREPROC_BACKEND"
    printf 'offline_preproc_backend=%s\n' "$OFFLINE_PREPROC_BACKEND"
    printf 'main_ring_degree=%s\n' "$MAIN_RING_DEGREE"
    printf 'main_pad_block_count=%s\n' "$MAIN_PAD_BLOCK_COUNT"
    printf 'main_structured_pad_version=%s\n' "$MAIN_STRUCTURED_PAD_VERSION"
    printf 'structured_pad_version=%s\n' "$MAIN_STRUCTURED_PAD_VERSION"
    printf 'main_modulus=%s\n' "4278255617"
    printf 'main_prg_domain=%s\n' "$MAIN_PRG_DOMAIN"
    printf 'main_security_status=%s\n' "$MAIN_SECURITY_STATUS"
    printf 'offline_ring_degree=%s\n' "$OFFLINE_RING_DEGREE"
    printf 'offline_pad_block_count=%s\n' "$OFFLINE_PAD_BLOCK_COUNT"
    printf 'offline_structured_pad_version=%s\n' "$OFFLINE_STRUCTURED_PAD_VERSION"
    printf 'offline_modulus=%s\n' "$OFFLINE_MODULUS"
    printf 'offline_prg_domain=%s\n' "$OFFLINE_PRG_DOMAIN"
    printf 'offline_security_status=%s\n' "$OFFLINE_SECURITY_STATUS"
    printf 'offline_q1=%s\n' "not-applicable"
    printf 'offline_q2=%s\n' "$OFFLINE_MODULUS"
    printf 'upstream_commit=%s\n' "$PIR_UPSTREAM_COMMIT"
    printf 'source_sha256=%s\n' "$(file_sha256 "$TEST_SOURCE")"
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'kernel=%s\n' "$(uname -sr)"
    printf 'memory_total_kib=%s\n' "$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)"
    printf 'memory_available_kib=%s\n' "$(effective_available_memory_kib)"
    printf 'logical_cpus=%s\n' "$(nproc)"
    printf 'compiler=%s\n' "$("$CXX" --version | sed -n '1p')"
    printf 'bazel_version=%s\n' "$PIR_BAZEL_VERSION"
    printf 'bazel_jobs=%s\n' "$PIR_BAZEL_JOBS"
    printf 'mode=%s\n' "$MODE"
    printf 'minimum_available_memory_kib=%s\n' "$MINIMUM_MEMORY_KIB"
    printf 'recommended_available_memory_kib=%s\n' "$RECOMMENDED_MEMORY_KIB"
    printf 'low_memory_override=%s\n' "${PIR_ALLOW_LOW_MEMORY:-0}"
    printf 'highway_mode=%s\n' "$([[ "${PIR_SCALAR:-0}" == "1" ]] && printf scalar || printf native-dispatch)"
    printf 'upstream_status=%s\n' "$(git -C "$PIR_UPSTREAM_DIR" status --porcelain=v1 --untracked-files=all | tr '\n' ';')"
    if [[ -r /sys/fs/cgroup/memory.max ]]; then
      printf 'cgroup_memory_max=%s\n' "$(< /sys/fs/cgroup/memory.max)"
    fi
  } >"$output_file"
}

prepare_1_source
pir_prepare_compiler
pir_resolve_bazel

readonly RUN_ID="$(pir_run_id)"
readonly RESULT_DIR="$PROFILE_LOG_ROOT/$RUN_ID"
mkdir "$RESULT_DIR" || pir_die "result directory already exists: $RESULT_DIR"

git -C "$PIR_UPSTREAM_DIR" diff --check
write_context "$RESULT_DIR/context-before.txt"

printf 'paper_profile=%s\n' "$PAPER_PROFILE"
printf 'preproc_profile=%s\n' "$PREPROC_PROFILE"
printf 'main_preproc_backend=%s\n' "$MAIN_PREPROC_BACKEND"
printf 'offline_preproc_backend=%s\n' "$OFFLINE_PREPROC_BACKEND"
printf 'offline_ring_degree=%s\n' "$OFFLINE_RING_DEGREE"
printf 'result_dir=%s\n' "$RESULT_DIR"
printf 'source_check=passed\n'
printf 'toolchain_check=passed\n'

if [[ "$MODE" == "--prepare-only" ]]; then
  printf 'status=prepared-only\n'
  exit 0
fi

readonly -a BUILD_COMMAND=(
  "${PIR_BAZEL_COMMAND[@]}"
  "${PIR_BAZEL_STARTUP_FLAGS[@]}"
  build
  "${PIR_BAZEL_ACTION_FLAGS[@]}"
  --verbose_failures
  "$PIR_TARGET"
)

cd -- "$PIR_UPSTREAM_DIR"
set +e
pir_print_command "${BUILD_COMMAND[@]}"
"${BUILD_COMMAND[@]}"
readonly BUILD_STATUS="$?"
set -e

if [[ "$BUILD_STATUS" -ne 0 ]]; then
  pir_die "1 GiB build failed (exit $BUILD_STATUS); inspect the terminal output"
fi
verify_1_source

readonly TEST_BINARY="$WORKSPACE_TEST_BINARY"
[[ -x "$TEST_BINARY" ]] || pir_die "configured test binary is missing: $TEST_BINARY"

if [[ "$MODE" == "--build-only" ]]; then
  printf 'status=built-only\n'
  printf 'binary=%s\n' "$TEST_BINARY"
  exit 0
fi

check_runtime_memory

ensure_no_active_test

readonly RUN_LOG="$RESULT_DIR/run.log"
readonly TIME_LOG="$RESULT_DIR/run.time.txt"
readonly VMSTAT_LOG="$RESULT_DIR/vmstat.log"
readonly META_LOG="$RESULT_DIR/metadata.txt"
offline_runtime_args=()
if [[ "$OFFLINE_PREPROC_BACKEND" == "ypir-offline-exact-ntt" ]]; then
  offline_runtime_args=("--offline-ring-degree=$OFFLINE_RING_DEGREE")
fi
readonly -a OFFLINE_RUNTIME_ARGS=("${offline_runtime_args[@]}")
readonly -a RUN_COMMAND=(
  env
  -u GTEST_FILTER
  -u GTEST_REPEAT
  -u GTEST_SHUFFLE
  -u GTEST_TOTAL_SHARDS
  -u GTEST_SHARD_INDEX
  -u GTEST_SHARD_STATUS_FILE
  "$TEST_BINARY"
  "--preproc-profile=$PREPROC_PROFILE"
  "${OFFLINE_RUNTIME_ARGS[@]}"
  --gtest_filter=HintlessSimplePir.EndToEndPIRTest
  --gtest_repeat=1
  --gtest_shuffle=0
)

VMSTAT_PID=""
cleanup_monitor() {
  if [[ -n "$VMSTAT_PID" ]]; then
    kill "$VMSTAT_PID" 2>/dev/null || true
    wait "$VMSTAT_PID" 2>/dev/null || true
    VMSTAT_PID=""
  fi
}
handle_signal() {
  local signal_name="$1"
  cleanup_monitor
  printf 'error: interrupted by %s\n' "$signal_name" >&2
  exit 130
}
trap cleanup_monitor EXIT
trap 'handle_signal SIGINT' INT
trap 'handle_signal SIGTERM' TERM
if command -v vmstat >/dev/null 2>&1; then
  vmstat -w -t 5 >"$VMSTAT_LOG" &
  VMSTAT_PID="$!"
else
  printf 'vmstat unavailable; no periodic memory monitor was recorded\n' >"$VMSTAT_LOG"
fi

set +e
{
  pir_print_command /usr/bin/time --verbose "--output=$TIME_LOG" "${RUN_COMMAND[@]}"
  /usr/bin/time --verbose "--output=$TIME_LOG" "${RUN_COMMAND[@]}"
} 2>&1 | tee "$RUN_LOG"
readonly -a RUN_PIPE_RESULTS=("${PIPESTATUS[@]}")
set -e
cleanup_monitor

readonly RUN_STATUS="${RUN_PIPE_RESULTS[0]}"
readonly RUN_TEE_STATUS="${RUN_PIPE_RESULTS[1]}"
{
  printf 'run_id=%s\n' "$RUN_ID"
  printf 'finished_at=%s\n' "$(date --iso-8601=seconds)"
  printf 'paper_profile=%s\n' "$PAPER_PROFILE"
  printf 'preproc_profile=%s\n' "$PREPROC_PROFILE"
  printf 'main_preproc_backend=%s\n' "$MAIN_PREPROC_BACKEND"
  printf 'offline_preproc_backend=%s\n' "$OFFLINE_PREPROC_BACKEND"
  printf 'main_ring_degree=%s\n' "$MAIN_RING_DEGREE"
  printf 'main_pad_block_count=%s\n' "$MAIN_PAD_BLOCK_COUNT"
  printf 'main_structured_pad_version=%s\n' "$MAIN_STRUCTURED_PAD_VERSION"
  printf 'structured_pad_version=%s\n' "$MAIN_STRUCTURED_PAD_VERSION"
  printf 'main_modulus=%s\n' "4278255617"
  printf 'main_prg_domain=%s\n' "$MAIN_PRG_DOMAIN"
  printf 'main_security_status=%s\n' "$MAIN_SECURITY_STATUS"
  printf 'offline_ring_degree=%s\n' "$OFFLINE_RING_DEGREE"
  printf 'offline_pad_block_count=%s\n' "$OFFLINE_PAD_BLOCK_COUNT"
  printf 'offline_structured_pad_version=%s\n' "$OFFLINE_STRUCTURED_PAD_VERSION"
  printf 'offline_modulus=%s\n' "$OFFLINE_MODULUS"
  printf 'offline_prg_domain=%s\n' "$OFFLINE_PRG_DOMAIN"
  printf 'offline_security_status=%s\n' "$OFFLINE_SECURITY_STATUS"
  printf 'offline_q1=%s\n' "not-applicable"
  printf 'offline_q2=%s\n' "$OFFLINE_MODULUS"
  printf 'target=%s\n' "$PIR_TARGET"
  printf 'upstream_commit=%s\n' "$PIR_UPSTREAM_COMMIT"
  printf 'source_sha256=%s\n' "$(file_sha256 "$TEST_SOURCE")"
  printf 'binary=%s\n' "$TEST_BINARY"
  printf 'binary_sha256=%s\n' "$(file_sha256 "$TEST_BINARY")"
  printf 'run_exit_code=%s\n' "$RUN_STATUS"
  printf 'tee_exit_code=%s\n' "$RUN_TEE_STATUS"
  printf 'run_log=%s\n' "$RUN_LOG"
  printf 'time_log=%s\n' "$TIME_LOG"
  printf 'vmstat_log=%s\n' "$VMSTAT_LOG"
} >"$META_LOG"
write_context "$RESULT_DIR/context-after.txt"

printf 'run_log=%s\n' "$RUN_LOG"
printf 'time_log=%s\n' "$TIME_LOG"
printf 'vmstat_log=%s\n' "$VMSTAT_LOG"
printf 'metadata_log=%s\n' "$META_LOG"

if [[ "$RUN_TEE_STATUS" -ne 0 ]]; then
  pir_die "tee failed while capturing the run log (exit $RUN_TEE_STATUS)"
fi
if [[ "$RUN_STATUS" -ne 0 ]]; then
  pir_die "1 GiB test failed (exit $RUN_STATUS); inspect $RUN_LOG and $TIME_LOG"
fi
grep -Fq 'database size: 1.0 GiB' "$RUN_LOG" \
  || pir_die "test passed without the expected 1.0 GiB profile marker"
grep -Fq 'Shards: 1 and Stacks: 1' "$RUN_LOG" \
  || pir_die "test passed without the expected stack-1 profile marker"
grep -Fq "preproc_profile=$PREPROC_PROFILE" "$RUN_LOG" \
  || pir_die "runtime preprocessing profile marker is missing"
grep -Fq "main_preproc_backend=$MAIN_PREPROC_BACKEND" "$RUN_LOG" \
  || pir_die "runtime main backend marker is missing"
grep -Fq "offline_preproc_backend=$OFFLINE_PREPROC_BACKEND" "$RUN_LOG" \
  || pir_die "runtime offline backend marker is missing"
grep -Fq "offline_ring_degree=$OFFLINE_RING_DEGREE" "$RUN_LOG" \
  || pir_die "runtime offline ring-degree marker is missing"
grep -Fq '[  PASSED  ] 1 test.' "$RUN_LOG" \
  || pir_die "GoogleTest success marker is missing from the run log"

printf 'status=passed\n'
