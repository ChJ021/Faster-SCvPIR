#!/usr/bin/env bash

# Build and run one frozen Small-Client vPIR paper-v1 experiment cell.

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MANIFEST="$PIR_NATIVE_ROOT/manifests/paper-v1.json"
readonly MANIFEST_CHECKSUM="$PIR_NATIVE_ROOT/manifests/paper-v1.sha256"
readonly CONFIG_HELPER="$PIR_NATIVE_ROOT/experiments/paper_config.py"
readonly SOURCE_PATCH="$PIR_NATIVE_ROOT/patches/ypir-ntt-preprocessing.patch"
readonly TEST_SOURCE="$PIR_UPSTREAM_DIR/hintless_simplepir/new_pir_test.cc"
readonly WORKSPACE_TEST_BINARY="$PIR_BAZEL_ROOT/symlinks/bazel-bin/hintless_simplepir/new_pir_test"

usage() {
  cat <<'EOF'
Usage: native/scripts/build-run-paper.sh --size=SIZE [OPTIONS]

Run one cell of the frozen honest-authenticated-hint paper-v1 experiment.

Required:
  --size=smoke|256mib|512mib|1gib|2gib|4gib

Profiles:
  --preproc-profile=dense
  --preproc-profile=negacyclic-main
  --preproc-profile=negacyclic-offline
  --preproc-profile=negacyclic-both

Legacy aliases baseline, ypir-main, distpir-offline, and hybrid are accepted
but normalized before logging.

Options:
  --query-index=N             Runtime database cell index (default: cols - 4).
  --offline-ring-degree=N     Compatibility option; must equal the frozen value.
  --cpu-set=LIST              Run through taskset --cpu-list LIST.
  --run-id=ID                 Stable non-overwriting result identifier.
  --skip-build                Reuse the already-built shared binary.
  --dry-run                   Validate arguments and print the resolved profile.
  --prepare-only              Also verify the patched checkout and toolchain.
  --build-only                Verify and build, but do not execute the test.
  -h, --help                  Show this help text.

Environment:
  PIR_ALLOW_LOW_MEMORY=1      Override the size-specific memory refusal.
  PIR_FORMAL_RUN=1            Enforce stable-host checks used by the matrix runner.
  PIR_ALLOW_UNSTABLE_CPU=1    Override a non-performance CPU governor warning.
  PIR_KEEP_PROXY=1            Preserve inherited proxy variables for Bazel.
  PIR_SCALAR=1                Compile Highway in scalar fallback mode.
EOF
}

size=""
profile="dense"
query_index=""
offline_ring_degree=""
cpu_set="${PIR_CPU_SET:-}"
run_id=""
mode="all"
skip_build="0"
for option in "$@"; do
  case "$option" in
    --size=*) size="${option#*=}" ;;
    --preproc-profile=*) profile="${option#*=}" ;;
    --query-index=*) query_index="${option#*=}" ;;
    --offline-ring-degree=*) offline_ring_degree="${option#*=}" ;;
    --cpu-set=*) cpu_set="${option#*=}" ;;
    --run-id=*) run_id="${option#*=}" ;;
    --skip-build) skip_build="1" ;;
    --dry-run | --prepare-only | --build-only)
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
[[ -n "$size" ]] || { usage >&2; pir_die "--size is required"; }
[[ -f "$CONFIG_HELPER" ]] || pir_die "paper profile helper is missing: $CONFIG_HELPER"
pir_require_command python3
pir_require_command sha256sum

config_output="$(
  python3 "$CONFIG_HELPER" --manifest "$MANIFEST" --checksum "$MANIFEST_CHECKSUM" \
    emit --size "$size" --profile "$profile"
)" || pir_die "paper-v1 manifest validation failed"
declare -A PAPER=()
while IFS='=' read -r key value; do
  [[ -n "$key" ]] || continue
  PAPER["$key"]="$value"
done <<<"$config_output"

required_keys=(
  manifest_id manifest_sha256 size profile rows columns record_bits stack_cells
  logical_bytes main_backend offline_backend main_ring_degree offline_ring_degree
  main_pad_blocks offline_pad_blocks minimum_memory_kib recommended_memory_kib
  default_query_index proof_bound_B sis_infinity_bound main_security_status
  offline_security_status bfv_security_status
)
for key in "${required_keys[@]}"; do
  [[ -n "${PAPER[$key]:-}" ]] || pir_die "manifest helper omitted $key"
done

readonly SIZE="${PAPER[size]}"
readonly PREPROC_PROFILE="${PAPER[profile]}"
readonly DB_ROWS="${PAPER[rows]}"
readonly DB_COLUMNS="${PAPER[columns]}"
readonly DB_RECORD_BITS="${PAPER[record_bits]}"
readonly DB_STACK_CELLS="${PAPER[stack_cells]}"
readonly LOGICAL_BYTES="${PAPER[logical_bytes]}"
readonly MAIN_PREPROC_BACKEND="${PAPER[main_backend]}"
readonly OFFLINE_PREPROC_BACKEND="${PAPER[offline_backend]}"
readonly MAIN_RING_DEGREE="${PAPER[main_ring_degree]}"
readonly FROZEN_OFFLINE_RING_DEGREE="${PAPER[offline_ring_degree]}"
readonly MAIN_PAD_BLOCK_COUNT="${PAPER[main_pad_blocks]}"
readonly OFFLINE_PAD_BLOCK_COUNT="${PAPER[offline_pad_blocks]}"
readonly MINIMUM_MEMORY_KIB="${PAPER[minimum_memory_kib]}"
readonly RECOMMENDED_MEMORY_KIB="${PAPER[recommended_memory_kib]}"
readonly MAIN_SECURITY_STATUS="${PAPER[main_security_status]}"
readonly OFFLINE_SECURITY_STATUS="${PAPER[offline_security_status]}"
readonly BFV_SECURITY_STATUS="${PAPER[bfv_security_status]}"
readonly MANIFEST_SHA256="${PAPER[manifest_sha256]}"
readonly PROOF_BOUND_B="${PAPER[proof_bound_B]}"
readonly SIS_INFINITY_BOUND="${PAPER[sis_infinity_bound]}"
readonly MODE="$mode"
readonly SKIP_BUILD="$skip_build"
[[ "$MODE" != "--build-only" || "$SKIP_BUILD" == "0" ]] \
  || pir_die "--skip-build cannot be combined with --build-only"

if [[ -n "$offline_ring_degree" && "$offline_ring_degree" != "$FROZEN_OFFLINE_RING_DEGREE" ]]; then
  pir_die "offline ring degree is frozen at $FROZEN_OFFLINE_RING_DEGREE for $SIZE/$PREPROC_PROFILE"
fi
if [[ "$FROZEN_OFFLINE_RING_DEGREE" == "0" && -n "$offline_ring_degree" ]]; then
  pir_die "--offline-ring-degree is only valid for a structured offline profile"
fi
readonly OFFLINE_RING_DEGREE="$FROZEN_OFFLINE_RING_DEGREE"

if [[ -z "$query_index" ]]; then
  query_index="${PAPER[default_query_index]}"
fi
[[ "$query_index" =~ ^[0-9]+$ ]] || pir_die "query index must be an unsigned integer"
readonly QUERY_INDEX="$query_index"
readonly TOTAL_CELLS=$((DB_ROWS * DB_COLUMNS))
((QUERY_INDEX < TOTAL_CELLS)) || pir_die "query index is outside the configured database"
readonly QUERY_ROW=$((QUERY_INDEX / DB_COLUMNS))
((QUERY_ROW % DB_STACK_CELLS == 0)) || pir_die "query index is not aligned to the configured stack"
((QUERY_ROW + DB_STACK_CELLS <= DB_ROWS)) || pir_die "stacked query extends past the configured database"

if [[ -n "$cpu_set" ]]; then
  [[ "$cpu_set" =~ ^[0-9,-]+$ ]] || pir_die "--cpu-set must contain only CPU numbers, commas, and ranges"
  pir_require_command taskset
  taskset --cpu-list "$cpu_set" true >/dev/null 2>&1 \
    || pir_die "--cpu-set does not select an available CPU"
fi
readonly CPU_SET="$cpu_set"
if [[ -n "$run_id" ]]; then
  [[ "$run_id" =~ ^[A-Za-z0-9._-]+$ ]] || pir_die "run id contains unsupported characters"
else
  run_id="$(pir_run_id)"
fi
readonly RUN_ID="$run_id"

file_sha256() {
  local digest
  digest="$(sha256sum "$1")"
  printf '%s\n' "${digest%% *}"
}

print_resolved_profile() {
  printf 'manifest_id=%s\n' "${PAPER[manifest_id]}"
  printf 'manifest_sha256=%s\n' "$MANIFEST_SHA256"
  printf 'database_profile=%s\n' "$SIZE"
  printf 'database_rows=%s\n' "$DB_ROWS"
  printf 'database_columns=%s\n' "$DB_COLUMNS"
  printf 'database_record_bits=%s\n' "$DB_RECORD_BITS"
  printf 'database_stack_cells=%s\n' "$DB_STACK_CELLS"
  printf 'database_logical_bytes=%s\n' "$LOGICAL_BYTES"
  printf 'preproc_profile=%s\n' "$PREPROC_PROFILE"
  printf 'main_preproc_backend=%s\n' "$MAIN_PREPROC_BACKEND"
  printf 'offline_preproc_backend=%s\n' "$OFFLINE_PREPROC_BACKEND"
  printf 'main_ring_degree=%s\n' "$MAIN_RING_DEGREE"
  printf 'offline_ring_degree=%s\n' "$OFFLINE_RING_DEGREE"
  printf 'main_pad_block_count=%s\n' "$MAIN_PAD_BLOCK_COUNT"
  printf 'offline_pad_block_count=%s\n' "$OFFLINE_PAD_BLOCK_COUNT"
  printf 'query_index=%s\n' "$QUERY_INDEX"
  printf 'proof_bound_B=%s\n' "$PROOF_BOUND_B"
  printf 'sis_infinity_bound=%s\n' "$SIS_INFINITY_BOUND"
  printf 'main_security_status=%s\n' "$MAIN_SECURITY_STATUS"
  printf 'offline_security_status=%s\n' "$OFFLINE_SECURITY_STATUS"
  printf 'bfv_security_status=%s\n' "$BFV_SECURITY_STATUS"
  printf 'minimum_available_memory_kib=%s\n' "$MINIMUM_MEMORY_KIB"
  printf 'recommended_available_memory_kib=%s\n' "$RECOMMENDED_MEMORY_KIB"
  printf 'cpu_set=%s\n' "${CPU_SET:-inherited}"
  printf 'client_main_pad_backend_lifecycle=ephemeral-per-operation\n'
  printf 'client_main_pad_backend_cached_bytes=0\n'
  printf 'run_id=%s\n' "$RUN_ID"
}

if [[ "$MODE" == "--dry-run" ]]; then
  print_resolved_profile
  printf 'status=dry-run\n'
  exit 0
fi

verify_patched_checkout() {
  pir_require_command grep
  pir_verify_upstream
  grep -Fq -- '--database-profile=' "$TEST_SOURCE" || pir_die "runtime database profile parser is missing"
  grep -Fq -- '--query-index=' "$TEST_SOURCE" || pir_die "runtime query index parser is missing"
  grep -Eq '\.qs[[:space:]]*=[[:space:]]*\{19988226643746817ULL,[[:space:]]*19988226643402753ULL\}' "$TEST_SOURCE" || pir_die "source BFV moduli differ from paper-v1"
  grep -Eq '\.gadget_log_bs[[:space:]]*=[[:space:]]*\{13,[[:space:]]*14\}' "$TEST_SOURCE" || pir_die "source gadget bases differ from paper-v1"
}

effective_available_memory_kib() {
  local available_kib cgroup_limit_bytes cgroup_used_bytes cgroup_available_kib
  available_kib="$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo)"
  [[ "$available_kib" =~ ^[0-9]+$ ]] || pir_die "could not read MemAvailable"
  if [[ -r /sys/fs/cgroup/memory.max && -r /sys/fs/cgroup/memory.current ]]; then
    cgroup_limit_bytes="$(< /sys/fs/cgroup/memory.max)"
    cgroup_used_bytes="$(< /sys/fs/cgroup/memory.current)"
    if [[ "$cgroup_limit_bytes" =~ ^[0-9]+$ && "$cgroup_used_bytes" =~ ^[0-9]+$ ]]; then
      if ((cgroup_used_bytes >= cgroup_limit_bytes)); then
        cgroup_available_kib=0
      else
        cgroup_available_kib=$(((cgroup_limit_bytes - cgroup_used_bytes) / 1024))
      fi
      ((cgroup_available_kib < available_kib)) && available_kib="$cgroup_available_kib"
    fi
  fi
  printf '%s\n' "$available_kib"
}

cpu_governors() {
  local governor_file governors=""
  for governor_file in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
    [[ -r "$governor_file" ]] || continue
    governors+="$(< "$governor_file"),"
  done
  printf '%s\n' "${governors%,}"
}

cpu_boost_state() {
  local value
  if [[ -r /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
    value="$(< /sys/devices/system/cpu/intel_pstate/no_turbo)"
    [[ "$value" == "0" ]] && printf 'enabled\n' || printf 'disabled\n'
  elif [[ -r /sys/devices/system/cpu/cpufreq/boost ]]; then
    value="$(< /sys/devices/system/cpu/cpufreq/boost)"
    [[ "$value" == "1" ]] && printf 'enabled\n' || printf 'disabled\n'
  else
    printf 'unavailable\n'
  fi
}

check_runtime_environment() {
  local memory_kib governors
  if [[ "${PIR_FORMAL_RUN:-0}" == "1" && -z "$CPU_SET" ]]; then
    pir_die "formal run requires an explicit --cpu-set to prevent CPU migration"
  fi
  memory_kib="$(effective_available_memory_kib)"
  printf 'effective_available_memory_kib=%s\n' "$memory_kib"
  if ((memory_kib < MINIMUM_MEMORY_KIB)); then
    if [[ "${PIR_ALLOW_LOW_MEMORY:-0}" != "1" ]]; then
      pir_die "effective memory is below the $((MINIMUM_MEMORY_KIB / 1024 / 1024)) GiB minimum for $SIZE"
    fi
    printf 'warning: low-memory override enabled; swap or OOM is possible\n' >&2
  elif ((memory_kib < RECOMMENDED_MEMORY_KIB)); then
    printf 'warning: available memory is below the recommended %s GiB for %s\n' "$((RECOMMENDED_MEMORY_KIB / 1024 / 1024))" "$SIZE" >&2
  fi
  governors="$(cpu_governors)"
  printf 'cpu_boost=%s\n' "$(cpu_boost_state)"
  if [[ "${PIR_FORMAL_RUN:-0}" == "1" && -n "$governors" && ! "$governors" =~ ^performance(,performance)*$ ]]; then
    if [[ "${PIR_ALLOW_UNSTABLE_CPU:-0}" != "1" ]]; then
      pir_die "formal run requires the performance CPU governor; runner will not change it automatically"
    fi
    printf 'warning: formal run is using non-performance CPU governors: %s\n' "$governors" >&2
  fi
}

write_context() {
  local output_file="$1"
  {
    printf 'schema=small-client-vpir-paper-v1-context\n'
    printf 'captured_at=%s\n' "$(date --iso-8601=seconds)"
    print_resolved_profile
    printf 'project_root=%s\n' "$PIR_PROJECT_ROOT"
    printf 'upstream_commit=%s\n' "$PIR_UPSTREAM_COMMIT"
    printf 'source_patch_sha256=%s\n' "$(file_sha256 "$SOURCE_PATCH")"
    printf 'source_sha256=%s\n' "$(file_sha256 "$TEST_SOURCE")"
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'kernel=%s\n' "$(uname -sr)"
    printf 'memory_total_kib=%s\n' "$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)"
    printf 'memory_available_kib=%s\n' "$(effective_available_memory_kib)"
    printf 'logical_cpus=%s\n' "$(nproc)"
    printf 'cpu_model=%s\n' "$(awk -F: '/^model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo)"
    printf 'cpu_microcode=%s\n' "$(awk -F: '/^microcode/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo)"
    printf 'cpu_governors=%s\n' "$(cpu_governors)"
    printf 'cpu_boost=%s\n' "$(cpu_boost_state)"
    printf 'load_average=%s\n' "$(< /proc/loadavg)"
    if command -v taskset >/dev/null 2>&1; then
      printf 'process_affinity=%s\n' "$(taskset -pc $$ 2>/dev/null || printf unavailable)"
    else
      printf 'process_affinity=unavailable\n'
    fi
    printf 'compiler=%s\n' "$("$CXX" --version | sed -n '1p')"
    printf 'bazel_version=%s\n' "$PIR_BAZEL_VERSION"
    printf 'bazel_jobs=%s\n' "$PIR_BAZEL_JOBS"
    printf 'formal_run=%s\n' "${PIR_FORMAL_RUN:-0}"
    printf 'low_memory_override=%s\n' "${PIR_ALLOW_LOW_MEMORY:-0}"
    printf 'unstable_cpu_override=%s\n' "${PIR_ALLOW_UNSTABLE_CPU:-0}"
    printf 'highway_mode=%s\n' "$([[ "${PIR_SCALAR:-0}" == "1" ]] && printf scalar || printf native-dispatch)"
    printf 'upstream_status=%s\n' "$(git -C "$PIR_UPSTREAM_DIR" status --porcelain=v1 --untracked-files=all | tr '\n' ';')"
  } >"$output_file"
}

pir_prepare_local_paths
verify_patched_checkout
pir_prepare_compiler
pir_resolve_bazel
if [[ "$MODE" == "--prepare-only" ]]; then
  print_resolved_profile
  printf 'source_patch_sha256=%s\n' "$(file_sha256 "$SOURCE_PATCH")"
  printf 'status=prepared-only\n'
  exit 0
fi

exec 9>"$PIR_LOG_DIR/paper-v1.execution.lock"
flock -n 9 || pir_die "another paper-v1 build/run currently owns the shared binary"

readonly -a BUILD_COMMAND=(
  "${PIR_BAZEL_COMMAND[@]}"
  "${PIR_BAZEL_STARTUP_FLAGS[@]}"
  build
  "${PIR_BAZEL_ACTION_FLAGS[@]}"
  --verbose_failures
  "$PIR_TARGET"
)
cd -- "$PIR_UPSTREAM_DIR"
if [[ "$SKIP_BUILD" == "0" ]]; then
  pir_print_command "${BUILD_COMMAND[@]}"
  "${BUILD_COMMAND[@]}" || pir_die "$SIZE build failed"
else
  printf 'build=reused\n'
fi
[[ -x "$WORKSPACE_TEST_BINARY" ]] || pir_die "test binary is missing after build"
if [[ "$MODE" == "--build-only" ]]; then
  print_resolved_profile
  printf 'binary=%s\n' "$WORKSPACE_TEST_BINARY"
  printf 'binary_sha256=%s\n' "$(file_sha256 "$WORKSPACE_TEST_BINARY")"
  printf 'status=built-only\n'
  exit 0
fi

check_runtime_environment
readonly PROFILE_LOG_ROOT="$PIR_LOG_DIR/paper-v1/$SIZE/$PREPROC_PROFILE"
mkdir -p "$PROFILE_LOG_ROOT"
readonly RESULT_DIR="$PROFILE_LOG_ROOT/$RUN_ID"
mkdir "$RESULT_DIR" || pir_die "result directory already exists: $RESULT_DIR"
write_context "$RESULT_DIR/context-before.txt"

offline_runtime_args=()
if [[ "$OFFLINE_RING_DEGREE" != "0" ]]; then
  offline_runtime_args=("--offline-ring-degree=$OFFLINE_RING_DEGREE")
fi
run_payload=(
  "$WORKSPACE_TEST_BINARY"
  "--database-profile=$SIZE"
  "--preproc-profile=$PREPROC_PROFILE"
  "${offline_runtime_args[@]}"
  "--query-index=$QUERY_INDEX"
  --gtest_filter=HintlessSimplePir.EndToEndPIRTest
  --gtest_repeat=1
  --gtest_shuffle=0
)
if [[ -n "$CPU_SET" ]]; then
  run_payload=(taskset --cpu-list "$CPU_SET" "${run_payload[@]}")
fi
readonly -a RUN_COMMAND=(
  env
  -u GTEST_FILTER -u GTEST_REPEAT -u GTEST_SHUFFLE
  -u GTEST_TOTAL_SHARDS -u GTEST_SHARD_INDEX -u GTEST_SHARD_STATUS_FILE
  "${run_payload[@]}"
)
readonly RUN_LOG="$RESULT_DIR/run.log"
readonly TIME_LOG="$RESULT_DIR/run.time.txt"
readonly VMSTAT_LOG="$RESULT_DIR/vmstat.log"
readonly META_LOG="$RESULT_DIR/metadata.txt"

VMSTAT_PID=""
cleanup_monitor() {
  if [[ -n "$VMSTAT_PID" ]]; then
    kill "$VMSTAT_PID" 2>/dev/null || true
    wait "$VMSTAT_PID" 2>/dev/null || true
    VMSTAT_PID=""
  fi
}
trap cleanup_monitor EXIT
if command -v vmstat >/dev/null 2>&1; then
  vmstat -w -t 5 >"$VMSTAT_LOG" &
  VMSTAT_PID="$!"
else
  printf 'vmstat unavailable\n' >"$VMSTAT_LOG"
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
readonly TEE_STATUS="${RUN_PIPE_RESULTS[1]}"

{
  print_resolved_profile
  printf 'finished_at=%s\n' "$(date --iso-8601=seconds)"
  printf 'target=%s\n' "$PIR_TARGET"
  printf 'upstream_commit=%s\n' "$PIR_UPSTREAM_COMMIT"
  printf 'source_patch_sha256=%s\n' "$(file_sha256 "$SOURCE_PATCH")"
  printf 'source_sha256=%s\n' "$(file_sha256 "$TEST_SOURCE")"
  printf 'binary=%s\n' "$WORKSPACE_TEST_BINARY"
  printf 'binary_sha256=%s\n' "$(file_sha256 "$WORKSPACE_TEST_BINARY")"
  printf 'run_exit_code=%s\n' "$RUN_STATUS"
  printf 'tee_exit_code=%s\n' "$TEE_STATUS"
  printf 'run_log=%s\n' "$RUN_LOG"
  printf 'time_log=%s\n' "$TIME_LOG"
  printf 'vmstat_log=%s\n' "$VMSTAT_LOG"
} >"$META_LOG"
write_context "$RESULT_DIR/context-after.txt"

[[ "$TEE_STATUS" == "0" ]] || pir_die "tee failed while capturing $RUN_LOG"
[[ "$RUN_STATUS" == "0" ]] || pir_die "$SIZE test failed; inspect $RUN_LOG"
grep -Fq "database_profile=$SIZE" "$RUN_LOG" || pir_die "database profile marker is missing"
grep -Fq "database_rows=$DB_ROWS" "$RUN_LOG" || pir_die "database row marker is missing"
grep -Fq "database_columns=$DB_COLUMNS" "$RUN_LOG" || pir_die "database column marker is missing"
grep -Fq "query_index=$QUERY_INDEX" "$RUN_LOG" || pir_die "query index marker is missing"
grep -Fq 'client_main_pad_backend_lifecycle=ephemeral-per-operation' "$RUN_LOG" || pir_die "client main-pad lifecycle marker is missing"
grep -Fq 'client_main_pad_backend_cached_bytes=0' "$RUN_LOG" || pir_die "client main-pad cache marker is missing"
grep -Fq 'Main Pad Backend State (KiB) : 0' "$RUN_LOG" || pir_die "client main-pad state metric is nonzero or missing"
grep -Fq "preproc_profile=$PREPROC_PROFILE" "$RUN_LOG" || pir_die "profile marker is missing"
grep -Fq "main_preproc_backend=$MAIN_PREPROC_BACKEND" "$RUN_LOG" || pir_die "main backend marker is missing"
grep -Fq "offline_preproc_backend=$OFFLINE_PREPROC_BACKEND" "$RUN_LOG" || pir_die "offline backend marker is missing"
grep -Fq "offline_ring_degree=$OFFLINE_RING_DEGREE" "$RUN_LOG" || pir_die "offline ring marker is missing"
grep -Fq '[  PASSED  ] 1 test.' "$RUN_LOG" || pir_die "GoogleTest success marker is missing"

printf 'result_dir=%s\n' "$RESULT_DIR"
printf 'status=passed\n'
