#!/usr/bin/env bash

# Building the shared experiment binary and executing one measured cell.
# The database geometry is passed explicitly from the manifest so the C++
# runner holds no size table of its own.

pir_build_cell() {
  local skip_build="$1"
  local -a build_command=(
    "${PIR_BAZEL_COMMAND[@]}"
    "${PIR_BAZEL_STARTUP_FLAGS[@]}"
    build
    "${PIR_BAZEL_ACTION_FLAGS[@]}"
    --verbose_failures
    "$PIR_TARGET"
  )

  pir_prepare_local_paths
  (cd -- "$PIR_PROJECT_ROOT" && [[ -f WORKSPACE.bazel ]]) \
    || pir_die "Bazel workspace is missing: $PIR_PROJECT_ROOT"
  if [[ "$skip_build" == "1" ]]; then
    printf 'build=reused\n'
  else
    pir_print_command "${build_command[@]}"
    (cd -- "$PIR_PROJECT_ROOT" && "${build_command[@]}") || pir_die "$SIZE build failed"
  fi
  [[ -x "$PIR_TEST_BINARY" ]] || pir_die "experiment binary is missing after build"
}

pir_execute_cell() {
  local result_dir="$1"
  local result_root
  local -a offline_runtime_args=() run_payload run_command
  local vmstat_pid="" run_status tee_status
  local run_log="$result_dir/run.log"
  local time_log="$result_dir/run.time.txt"
  local vmstat_log="$result_dir/vmstat.log"

  result_root="$(dirname -- "$result_dir")"
  mkdir -p "$result_root"
  mkdir "$result_dir" || pir_die "result directory already exists: $result_dir"
  pir_write_context "$result_dir/context-before.txt"

  if [[ "$OFFLINE_RING_DEGREE" != "0" ]]; then
    offline_runtime_args=("--offline-ring-degree=$OFFLINE_RING_DEGREE")
  fi
  run_payload=(
    "$PIR_TEST_BINARY"
    "--database-profile=$SIZE"
    "--db-rows=$DB_ROWS"
    "--db-columns=$DB_COLUMNS"
    "--db-record-bits=$DB_RECORD_BITS"
    "--db-stack-cells=$DB_STACK_CELLS"
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
  run_command=(
    env
    -u GTEST_FILTER -u GTEST_REPEAT -u GTEST_SHUFFLE
    -u GTEST_TOTAL_SHARDS -u GTEST_SHARD_INDEX -u GTEST_SHARD_STATUS_FILE
    "${run_payload[@]}"
  )

  cleanup_vmstat() {
    if [[ -n "$vmstat_pid" ]]; then
      kill "$vmstat_pid" 2>/dev/null || true
      wait "$vmstat_pid" 2>/dev/null || true
      vmstat_pid=""
    fi
  }
  trap cleanup_vmstat EXIT
  if command -v vmstat >/dev/null 2>&1; then
    vmstat -w -t 5 >"$vmstat_log" &
    vmstat_pid="$!"
  else
    printf 'vmstat unavailable\n' >"$vmstat_log"
  fi

  local -a pipe_results
  set +e
  {
    pir_print_command /usr/bin/time --verbose "--output=$time_log" "${run_command[@]}"
    /usr/bin/time --verbose "--output=$time_log" "${run_command[@]}"
  } 2>&1 | tee "$run_log"
  pipe_results=("${PIPESTATUS[@]}")
  set -e
  cleanup_vmstat
  trap - EXIT
  run_status="${pipe_results[0]}"
  tee_status="${pipe_results[1]}"

  pir_write_run_metadata "$result_dir/metadata.txt" \
    "$run_status" "$tee_status" "$PIR_TEST_BINARY" "$run_log" "$time_log" "$vmstat_log"
  pir_write_context "$result_dir/context-after.txt"

  [[ "$tee_status" == "0" ]] || pir_die "tee failed while capturing $run_log"
  [[ "$run_status" == "0" ]] || pir_die "$SIZE test failed; inspect $run_log"
  pir_validate_run_log "$run_log"

  printf 'result_dir=%s\n' "$result_dir"
  printf 'status=passed\n'
}
