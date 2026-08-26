#!/usr/bin/env bash

# Prepare, build, and run the author's 512 MiB honest-H paper profile in place.
#
# This script intentionally does not call pir_verify_upstream after changing the
# profile: that verifier is the immutable 2 MiB baseline gate.  Instead, this
# file enforces the pinned commit, both approved Clang 18 patches, and the exact
# post-edit SHA-256 of new_pir_test.cc.

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly PAPER_PROFILE="honest-h-paper-512mib"
readonly TEST_SOURCE="$PIR_UPSTREAM_DIR/hintless_simplepir/new_pir_test.cc"
readonly SERVER_SOURCE="$PIR_UPSTREAM_DIR/hintless_simplepir/server.cc"
readonly STAGE0_PATCH="$PIR_NATIVE_ROOT/patches/stage0-preprocessing-timers.patch"
readonly TEST_SOURCE_2MIB_SHA256="afa4a941c3fa63f8c754e383fce07eb205ba26aed68e9a34c8a3cea043e67e01"
readonly TEST_SOURCE_512MIB_BASE_SHA256="bf9f159dd8887df58984cb21ee38dfeed8a52221800a9204e6feb5648ba87a91"
readonly TEST_SOURCE_512MIB_STAGE0_SHA256="928389846c02d37d6db3e8e664564d72f9a6a5d787e8254aabd9db4aaf96dbd7"
readonly SERVER_SOURCE_BASE_SHA256="950b084d25faf9b6cb2bc70328cdc6ef66aa0b780224fc60f42c083bf78ad388"
readonly SERVER_SOURCE_STAGE0_SHA256="4cbb8c7b4991b50cf6f047b775a7079fb315199634c8b580ca410f108b7113b9"
readonly STAGE0_PATCH_SHA256="07f574f93884e039cbfa2b962fe7319e8f058208b68c87b38d8847c1fcab3b81"
readonly MINIMUM_MEMORY_KIB=$((12 * 1024 * 1024))
readonly RECOMMENDED_MEMORY_KIB=$((16 * 1024 * 1024))

usage() {
  cat <<'EOF'
Usage: native/scripts/build-run-paper-512mib.sh [OPTION]

Prepare the current upstream checkout in place for the author's 512 MiB
honest-H profile, build it with the pinned project-local Bazel toolchain, and
run HintlessSimplePir.EndToEndPIRTest while recording resource usage. Build
and test output is displayed live and mirrored to the run-specific log files.
Stage-0 timing records are also extracted to stage0-timings.tsv.

Options:
  --prepare-only  Validate and change the three profile constants, then stop.
  --build-only    Prepare and build, but do not run the memory-intensive test.
  -h, --help      Show this help text.

Environment:
  PIR_ALLOW_LOW_MEMORY=1  Override the <12 GiB runtime refusal.
  PIR_KEEP_PROXY=1        Preserve caller HTTP(S)/ALL proxy variables.
  PIR_SCALAR=1            Compile Highway in scalar fallback mode.

The operation is idempotent: an exact 512 MiB source is accepted unchanged.
It does not preserve a second 2 MiB worktree.  Existing historical logs remain
under native/logs; new artifacts go under native/logs/512mib/<run-id>/.
EOF
}

if (($# > 1)); then
  usage >&2
  pir_die "expected at most one option"
fi

readonly MODE="${1:-all}"
case "$MODE" in
  all | --prepare-only | --build-only) ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    pir_die "unsupported option: $MODE"
    ;;
esac

pir_require_command git
pir_require_command sha256sum
pir_require_command sed
pir_require_command grep
pir_require_command tee
pir_require_command stdbuf
pir_require_command awk
pir_require_command cat
pir_require_command wc
pir_require_command flock
pir_require_command readlink
pir_require_command /usr/bin/time

[[ "$(uname -m)" == "x86_64" ]] \
  || pir_die "the bundled Bazel binary and validated native profile require x86_64"

pir_prepare_local_paths
readonly PROFILE_LOG_ROOT="$PIR_LOG_DIR/512mib"
mkdir -p "$PROFILE_LOG_ROOT"

# Prevent two copies of this orchestration script from allocating the paper
# profile concurrently.  Manual binary launches are checked again before run.
exec 9>"$PROFILE_LOG_ROOT/.execution.lock"
flock -n 9 || pir_die "another 512 MiB build/run script already holds the execution lock"

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

  local actual_url actual_commit client_digest mat_digest eigen_digest
  local stage0_patch_digest
  actual_url="$(git -C "$PIR_UPSTREAM_DIR" remote get-url origin)"
  actual_commit="$(git -C "$PIR_UPSTREAM_DIR" rev-parse HEAD)"
  [[ "$actual_url" == "$PIR_UPSTREAM_URL" ]] \
    || pir_die "origin mismatch: expected $PIR_UPSTREAM_URL, got $actual_url"
  [[ "$actual_commit" == "$PIR_UPSTREAM_COMMIT" ]] \
    || pir_die "commit mismatch: expected $PIR_UPSTREAM_COMMIT, got $actual_commit"

  client_digest="$(file_sha256 "$PIR_UPSTREAM_DIR/hintless_simplepir/client.cc")"
  mat_digest="$(file_sha256 "$PIR_UPSTREAM_DIR/verisimplepir/src/lib/pir/mat.cpp")"
  [[ "$client_digest" == "$PIR_PATCHED_CLIENT_SHA256" ]] \
    || pir_die "approved client.cc compatibility patch checksum mismatch"
  [[ "$mat_digest" == "$PIR_PATCHED_MAT_SHA256" ]] \
    || pir_die "approved mat.cpp compatibility patch checksum mismatch"

  [[ -f "$PIR_EIGEN_ARCHIVE" ]] \
    || pir_die "pinned Eigen archive is missing: $PIR_EIGEN_ARCHIVE"
  [[ -f "$PIR_EIGEN_DIR/BUILD.bazel" && -f "$PIR_EIGEN_DIR/WORKSPACE.bazel" ]] \
    || pir_die "project-local Eigen Bazel repository is incomplete"
  eigen_digest="$(file_sha256 "$PIR_EIGEN_ARCHIVE")"
  [[ "$eigen_digest" == "$PIR_EIGEN_SHA256" ]] \
    || pir_die "pinned Eigen archive checksum mismatch"

  [[ -f "$STAGE0_PATCH" ]] \
    || pir_die "stage-0 instrumentation patch is missing: $STAGE0_PATCH"
  stage0_patch_digest="$(file_sha256 "$STAGE0_PATCH")"
  [[ "$stage0_patch_digest" == "$STAGE0_PATCH_SHA256" ]] \
    || pir_die "stage-0 instrumentation patch checksum mismatch"

  local mode_header
  mode_header="$PIR_UPSTREAM_DIR/verisimplepir/src/lib/pir/utils.h"
  grep -Eq '^#define[[:space:]]+BSGS([[:space:]]|$)' "$mode_header" \
    || pir_die "BSGS must be enabled for the paper profile"
  if grep -Eq '^#define[[:space:]]+(FAKE_RUN|SH_RUN)([[:space:]]|$)' "$mode_header"; then
    pir_die "FAKE_RUN and SH_RUN must remain disabled"
  fi
}

verify_512_source_and_status() {
  local source_digest server_digest tracked_changes expected_changes
  source_digest="$(file_sha256 "$TEST_SOURCE")"
  server_digest="$(file_sha256 "$SERVER_SOURCE")"
  [[ "$source_digest" == "$TEST_SOURCE_512MIB_STAGE0_SHA256" ]] \
    || pir_die "stage-0 512 MiB test source checksum mismatch: got $source_digest"
  [[ "$server_digest" == "$SERVER_SOURCE_STAGE0_SHA256" ]] \
    || pir_die "stage-0 server source checksum mismatch: got $server_digest"

  grep -Eq 'const int rows_db[[:space:]]*=[[:space:]]*32768;' "$TEST_SOURCE" \
    || pir_die "paper profile rows_db=32768 is missing"
  grep -Eq 'const int cols_db[[:space:]]*=[[:space:]]*16384;' "$TEST_SOURCE" \
    || pir_die "paper profile cols_db=16384 is missing"
  grep -Eq '^[[:space:]]*\.db_stack_cells[[:space:]]*=[[:space:]]*8,' "$TEST_SOURCE" \
    || pir_die "paper profile db_stack_cells=8 is missing"
  grep -Eq '^[[:space:]]*\.db_record_bit_size[[:space:]]*=[[:space:]]*8,' "$TEST_SOURCE" \
    || pir_die "paper profile db_record_bit_size=8 is missing"
  grep -Eq '^bool use_static_db[[:space:]]*=[[:space:]]*true;' "$TEST_SOURCE" \
    || pir_die "paper profile requires the static database path"
  grep -Fq '[STAGE0_TIMING] scope=' "$TEST_SOURCE" \
    || pir_die "stage-0 test timing marker is missing"
  grep -Fq '[STAGE0_TIMING] scope=server stage=' "$SERVER_SOURCE" \
    || pir_die "stage-0 server timing marker is missing"

  tracked_changes="$(git -C "$PIR_UPSTREAM_DIR" status --porcelain=v1 --untracked-files=all)"
  expected_changes=$' M hintless_simplepir/client.cc\n M hintless_simplepir/new_pir_test.cc\n M hintless_simplepir/server.cc\n M verisimplepir/src/lib/pir/mat.cpp'
  [[ "$tracked_changes" == "$expected_changes" ]] \
    || pir_die "upstream changes are not exactly the compatibility patches, 512 MiB profile, and stage-0 instrumentation"
}

prepare_512_source() {
  verify_common_checkout

  local source_digest server_digest
  source_digest="$(file_sha256 "$TEST_SOURCE")"
  if [[ "$source_digest" == "$TEST_SOURCE_2MIB_SHA256" ]]; then
    # The immutable baseline verifier gives stronger assurance before the
    # profile edit, including the exact expected two-file dirty status.
    pir_verify_upstream
    sed -i -E \
      -e 's/^const int rows_db[[:space:]]*=[[:space:]]*2048;$/const int rows_db = 32768;/' \
      -e 's/^const int cols_db[[:space:]]*=[[:space:]]*1024;$/const int cols_db = 16384;/' \
      -e 's/^[[:space:]]*\.db_stack_cells[[:space:]]*=[[:space:]]*1,$/    .db_stack_cells = 8,/' \
      "$TEST_SOURCE"
  elif [[ "$source_digest" == "$TEST_SOURCE_512MIB_BASE_SHA256" ]]; then
    printf 'profile_source=already-prepared\n'
  elif [[ "$source_digest" == "$TEST_SOURCE_512MIB_STAGE0_SHA256" ]]; then
    printf 'profile_source=already-prepared-and-instrumented\n'
  else
    pir_die "new_pir_test.cc is neither the pinned 2 MiB source nor the exact 512 MiB profile (sha256=$source_digest)"
  fi

  source_digest="$(file_sha256 "$TEST_SOURCE")"
  server_digest="$(file_sha256 "$SERVER_SOURCE")"
  if [[ "$source_digest" == "$TEST_SOURCE_512MIB_BASE_SHA256" \
     && "$server_digest" == "$SERVER_SOURCE_BASE_SHA256" ]]; then
    git -C "$PIR_UPSTREAM_DIR" apply --check "$STAGE0_PATCH"
    git -C "$PIR_UPSTREAM_DIR" apply "$STAGE0_PATCH"
    printf 'stage0_instrumentation=applied\n'
  elif [[ "$source_digest" == "$TEST_SOURCE_512MIB_STAGE0_SHA256" \
       && "$server_digest" == "$SERVER_SOURCE_STAGE0_SHA256" ]]; then
    printf 'stage0_instrumentation=already-applied\n'
  else
    pir_die "stage-0 instrumentation source state is inconsistent"
  fi

  verify_512_source_and_status
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
      pir_die "effective memory is below 12 GiB; set PIR_ALLOW_LOW_MEMORY=1 only for an intentional swap/OOM-risk experiment"
    fi
    printf 'warning: low-memory override enabled; the 512 MiB run may swap heavily or be OOM-killed\n' >&2
  elif ((memory_kib < RECOMMENDED_MEMORY_KIB)); then
    printf 'warning: less than the recommended 16 GiB is available to this process\n' >&2
  fi
}

write_context() {
  local output_file="$1"
  {
    printf 'schema=small-client-vpir-paper-512mib-context-v1\n'
    printf 'captured_at=%s\n' "$(date --iso-8601=seconds)"
    printf 'project_root=%s\n' "$PIR_PROJECT_ROOT"
    printf 'profile=%s\n' "$PAPER_PROFILE"
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

prepare_512_source
pir_prepare_compiler
pir_resolve_bazel

readonly RUN_ID="$(pir_run_id)"
readonly RESULT_DIR="$PROFILE_LOG_ROOT/$RUN_ID"
mkdir "$RESULT_DIR" || pir_die "result directory already exists: $RESULT_DIR"

git -C "$PIR_UPSTREAM_DIR" diff --check
git -C "$PIR_UPSTREAM_DIR" diff -- hintless_simplepir/new_pir_test.cc \
  >"$RESULT_DIR/512mib-parameters.patch"
git -C "$PIR_UPSTREAM_DIR" diff -- \
  hintless_simplepir/new_pir_test.cc hintless_simplepir/server.cc \
  >"$RESULT_DIR/effective-stage0-source.patch"
sha256sum "$TEST_SOURCE" >"$RESULT_DIR/new_pir_test.cc.sha256"
sha256sum "$SERVER_SOURCE" >"$RESULT_DIR/server.cc.sha256"
sha256sum "$STAGE0_PATCH" >"$RESULT_DIR/stage0-preprocessing-timers.patch.sha256"
write_context "$RESULT_DIR/context-before.txt"

printf 'profile=%s\n' "$PAPER_PROFILE"
printf 'result_dir=%s\n' "$RESULT_DIR"
printf 'source_check=passed\n'
printf 'toolchain_check=passed\n'

if [[ "$MODE" == "--prepare-only" ]]; then
  printf 'status=prepared-only\n'
  exit 0
fi

readonly BUILD_LOG="$RESULT_DIR/build.log"
readonly BUILD_TIME_LOG="$RESULT_DIR/build.time.txt"
readonly -a BUILD_COMMAND=(
  /usr/bin/time --verbose "--output=$BUILD_TIME_LOG"
  "${PIR_BAZEL_COMMAND[@]}"
  "${PIR_BAZEL_STARTUP_FLAGS[@]}"
  build
  "${PIR_BAZEL_ACTION_FLAGS[@]}"
  --verbose_failures
  "$PIR_TARGET"
)

cd -- "$PIR_UPSTREAM_DIR"
set +e
{
  pir_print_command "${BUILD_COMMAND[@]}"
  "${BUILD_COMMAND[@]}"
} 2>&1 | tee "$BUILD_LOG"
readonly -a BUILD_PIPE_RESULTS=("${PIPESTATUS[@]}")
set -e

readonly BUILD_STATUS="${BUILD_PIPE_RESULTS[0]}"
readonly BUILD_TEE_STATUS="${BUILD_PIPE_RESULTS[1]}"
printf '%s\n' "$BUILD_STATUS" >"$RESULT_DIR/build-exit-code.txt"
if [[ "$BUILD_TEE_STATUS" -ne 0 ]]; then
  pir_die "tee failed while capturing the build log (exit $BUILD_TEE_STATUS)"
fi
if [[ "$BUILD_STATUS" -ne 0 ]]; then
  pir_die "512 MiB build failed (exit $BUILD_STATUS); inspect $BUILD_LOG"
fi
verify_512_source_and_status

readonly TEST_BINARY="$WORKSPACE_TEST_BINARY"
[[ -x "$TEST_BINARY" ]] || pir_die "configured test binary is missing: $TEST_BINARY"
sha256sum "$TEST_BINARY" >"$RESULT_DIR/binary.sha256"

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
readonly STAGE0_TIMINGS_LOG="$RESULT_DIR/stage0-timings.tsv"
readonly -a RUN_COMMAND=(
  env
  -u GTEST_FILTER
  -u GTEST_REPEAT
  -u GTEST_SHUFFLE
  -u GTEST_TOTAL_SHARDS
  -u GTEST_SHARD_INDEX
  -u GTEST_SHARD_STATUS_FILE
  stdbuf
  -oL
  -eL
  "$TEST_BINARY"
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
awk '
  BEGIN { print "scope\tstage\tduration_ms\tduration_s" }
  /^\[STAGE0_TIMING\]/ {
    scope = stage = duration_ms = duration_s = ""
    for (i = 2; i <= NF; ++i) {
      split($i, pair, "=")
      if (pair[1] == "scope") scope = pair[2]
      if (pair[1] == "stage") stage = pair[2]
      if (pair[1] == "duration_ms") duration_ms = pair[2]
      if (pair[1] == "duration_s") duration_s = pair[2]
    }
    if (scope != "" && stage != "" && duration_ms != "" && duration_s != "") {
      print scope "\t" stage "\t" duration_ms "\t" duration_s
    }
  }
' "$RUN_LOG" >"$STAGE0_TIMINGS_LOG"
printf '%s\n' 'Stage-0 timing summary:'
cat "$STAGE0_TIMINGS_LOG"

readonly STAGE0_TIMING_COUNT="$(( $(wc -l <"$STAGE0_TIMINGS_LOG") - 1 ))"
{
  printf 'run_id=%s\n' "$RUN_ID"
  printf 'finished_at=%s\n' "$(date --iso-8601=seconds)"
  printf 'profile=%s\n' "$PAPER_PROFILE"
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
  printf 'stage0_timings_log=%s\n' "$STAGE0_TIMINGS_LOG"
  printf 'stage0_timing_count=%s\n' "$STAGE0_TIMING_COUNT"
} >"$META_LOG"
write_context "$RESULT_DIR/context-after.txt"

printf 'run_log=%s\n' "$RUN_LOG"
printf 'time_log=%s\n' "$TIME_LOG"
printf 'vmstat_log=%s\n' "$VMSTAT_LOG"
printf 'stage0_timings_log=%s\n' "$STAGE0_TIMINGS_LOG"
printf 'metadata_log=%s\n' "$META_LOG"

if [[ "$RUN_TEE_STATUS" -ne 0 ]]; then
  pir_die "tee failed while capturing the run log (exit $RUN_TEE_STATUS)"
fi
if [[ "$RUN_STATUS" -ne 0 ]]; then
  pir_die "512 MiB test failed (exit $RUN_STATUS); inspect $RUN_LOG and $TIME_LOG"
fi
if ((STAGE0_TIMING_COUNT < 20)); then
  pir_die "only $STAGE0_TIMING_COUNT stage-0 timing records were captured"
fi
grep -Fq $'server\tmain_hint_matrix_product\t' "$STAGE0_TIMINGS_LOG" \
  || pir_die "main hint timing is missing from stage0-timings.tsv"
grep -Fq $'global\toffline_H2_matrix_product\t' "$STAGE0_TIMINGS_LOG" \
  || pir_die "offline H2 timing is missing from stage0-timings.tsv"
grep -Fq $'client_local\toffline_challenge_encrypt\t' "$STAGE0_TIMINGS_LOG" \
  || pir_die "offline challenge encryption timing is missing from stage0-timings.tsv"
grep -Fq 'database size: 0.5 GiB' "$RUN_LOG" \
  || pir_die "test passed without the expected 0.5 GiB profile marker"
grep -Fq 'Shards: 1 and Stacks: 8' "$RUN_LOG" \
  || pir_die "test passed without the expected stack-8 profile marker"
grep -Fq '[  PASSED  ] 1 test.' "$RUN_LOG" \
  || pir_die "GoogleTest success marker is missing from the run log"

printf 'status=passed\n'
