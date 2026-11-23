#!/usr/bin/env bash

# Human-readable profile dumps and the per-run provenance records.

pir_print_resolved_profile() {
  printf 'manifest_id=%s\n' "${PAPER[manifest_id]}"
  printf 'manifest_sha256=%s\n' "$MANIFEST_SHA256"
  printf 'database_profile=%s\n' "$SIZE"
  printf 'database_rows=%s\n' "$DB_ROWS"
  printf 'database_columns=%s\n' "$DB_COLUMNS"
  printf 'database_record_bits=%s\n' "$DB_RECORD_BITS"
  printf 'database_stack_cells=%s\n' "$DB_STACK_CELLS"
  printf 'database_logical_bytes=%s\n' "$LOGICAL_BYTES"
  printf 'database_offline_ring_degree=%s\n' "$OFFLINE_RING_DEGREE"
  printf 'preproc_profile=%s\n' "$PREPROC_PROFILE"
  printf 'main_preproc_backend=%s\n' "$MAIN_PREPROC_BACKEND"
  printf 'offline_preproc_backend=%s\n' "$OFFLINE_PREPROC_BACKEND"
  printf 'main_ring_degree=%s\n' "$MAIN_RING_DEGREE"
  printf 'offline_ring_degree=%s\n' "$OFFLINE_RING_DEGREE"
  printf 'main_pad_block_count=%s\n' "$MAIN_PAD_BLOCK_COUNT"
  printf 'offline_pad_block_count=%s\n' "$OFFLINE_PAD_BLOCK_COUNT"
  printf 'query_index=%s\n' "$QUERY_INDEX"
  printf 'cpu_set=%s\n' "${CPU_SET:-inherited}"
  printf 'client_main_pad_backend_lifecycle=ephemeral-per-operation\n'
  printf 'client_main_pad_backend_cached_bytes=0\n'
  printf 'run_id=%s\n' "$RUN_ID"
}

pir_write_context() {
  local output_file="$1"
  {
    printf 'schema=small-client-vpir-paper-v1-context\n'
    printf 'captured_at=%s\n' "$(date --iso-8601=seconds)"
    pir_print_resolved_profile
    printf 'project_root=%s\n' "$PIR_PROJECT_ROOT"
    printf 'upstream_url=%s\n' "$PIR_UPSTREAM_URL"
    printf 'upstream_commit=%s\n' "$PIR_UPSTREAM_COMMIT"
    printf 'source_sha256=%s\n' "$(file_sha256 "$PIR_TEST_SOURCE")"
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
    printf 'unstable_cpu_override=%s\n' "${PIR_ALLOW_UNSTABLE_CPU:-0}"
    printf 'highway_mode=%s\n' "$([[ "${PIR_SCALAR:-0}" == "1" ]] && printf scalar || printf native-dispatch)"
  } >"$output_file"
}

pir_write_run_metadata() {
  local output_file="$1"
  local run_status="$2"
  local tee_status="$3"
  local binary="$4"
  local run_log="$5"
  local time_log="$6"
  local vmstat_log="$7"
  {
    pir_print_resolved_profile
    printf 'finished_at=%s\n' "$(date --iso-8601=seconds)"
    printf 'target=%s\n' "$PIR_TARGET"
    printf 'upstream_commit=%s\n' "$PIR_UPSTREAM_COMMIT"
    printf 'source_sha256=%s\n' "$(file_sha256 "$PIR_TEST_SOURCE")"
    printf 'binary=%s\n' "$binary"
    printf 'binary_sha256=%s\n' "$(file_sha256 "$binary")"
    printf 'run_exit_code=%s\n' "$run_status"
    printf 'tee_exit_code=%s\n' "$tee_status"
    printf 'run_log=%s\n' "$run_log"
    printf 'time_log=%s\n' "$time_log"
    printf 'vmstat_log=%s\n' "$vmstat_log"
  } >"$output_file"
}

# The experiment binary must have echoed back the exact cell it was asked to run.
pir_validate_run_log() {
  local run_log="$1"
  local marker
  local -a required_markers=(
    "database_profile=$SIZE"
    "database_rows=$DB_ROWS"
    "database_columns=$DB_COLUMNS"
    "query_index=$QUERY_INDEX"
    'client_main_pad_backend_lifecycle=ephemeral-per-operation'
    'client_main_pad_backend_cached_bytes=0'
    'Main Pad Backend State (KiB) : 0'
    "preproc_profile=$PREPROC_PROFILE"
    "main_preproc_backend=$MAIN_PREPROC_BACKEND"
    "offline_preproc_backend=$OFFLINE_PREPROC_BACKEND"
    "offline_ring_degree=$OFFLINE_RING_DEGREE"
    '[  PASSED  ] 1 test.'
  )
  for marker in "${required_markers[@]}"; do
    grep -Fq -- "$marker" "$run_log" || pir_die "run log is missing marker: $marker"
  done
}
