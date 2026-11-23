#!/usr/bin/env bash

# Build and run one frozen Small-Client vPIR paper-v1 experiment cell.
# This entry point only parses options and sequences the feature modules:
#   lib/common.sh    shared paths and helpers
#   lib/toolchain.sh compiler and Bazel discovery
#   lib/manifest.sh  cell resolution from the paper-v1 manifest
#   lib/checks.sh    host memory and CPU checks
#   lib/report.sh    profile dumps and provenance records
#   lib/cell.sh      build and measured execution

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/toolchain.sh
source "$SCRIPT_DIR/lib/toolchain.sh"
# shellcheck source=lib/manifest.sh
source "$SCRIPT_DIR/lib/manifest.sh"
# shellcheck source=lib/checks.sh
source "$SCRIPT_DIR/lib/checks.sh"
# shellcheck source=lib/report.sh
source "$SCRIPT_DIR/lib/report.sh"
# shellcheck source=lib/cell.sh
source "$SCRIPT_DIR/lib/cell.sh"

usage() {
  cat <<'EOF'
Usage: scripts/build-run-paper.sh --size=SIZE [OPTIONS]

Run one cell of the honest-authenticated-hint paper-v1 experiment.
Sizes and database layouts come from manifests/paper-v1.json; run
`python3 experiments/paper_config.py list` to see them.

Required:
  --size=SIZE                 Manifest size name (for example 256mib).

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
  --prepare-only              Validate the cell and report the toolchain only.
  --build-only                Build the shared binary without executing a run.
  -h, --help                  Show this help text.

Environment:
  PIR_FORMAL_RUN=1            Enforce stable-host checks used by the matrix runner.
  PIR_ALLOW_UNSTABLE_CPU=1    Override a non-performance CPU governor warning.
  PIR_KEEP_PROXY=1            Preserve inherited proxy variables for Bazel.
  PIR_SCALAR=1                Compile Highway in scalar fallback mode.
EOF
}

argv=("$@")
size=""
profile="dense"
query_index=""
offline_ring_degree=""
cpu_set="${PIR_CPU_SET:-}"
run_id=""
mode="all"
skip_build="0"
for option in "${argv[@]}"; do
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

pir_load_cell_config "$size" "$profile"
pir_finalize_cell_config "$offline_ring_degree" "$query_index"

MODE="$mode"
SKIP_BUILD="$skip_build"
[[ "$MODE" != "--build-only" || "$SKIP_BUILD" == "0" ]] \
  || pir_die "--skip-build cannot be combined with --build-only"

if [[ -n "$cpu_set" ]]; then
  [[ "$cpu_set" =~ ^[0-9,-]+$ ]] || pir_die "--cpu-set must contain only CPU numbers, commas, and ranges"
  pir_require_command taskset
  taskset --cpu-list "$cpu_set" true >/dev/null 2>&1 \
    || pir_die "--cpu-set does not select an available CPU"
fi
CPU_SET="$cpu_set"
if [[ -n "$run_id" ]]; then
  [[ "$run_id" =~ ^[A-Za-z0-9._-]+$ ]] || pir_die "run id contains unsupported characters"
else
  run_id="$(pir_run_id)"
fi
RUN_ID="$run_id"

if [[ "$MODE" == "--dry-run" ]]; then
  pir_print_resolved_profile
  printf 'status=dry-run\n'
  exit 0
fi

pir_prepare_compiler
pir_resolve_bazel
if [[ "$MODE" == "--prepare-only" ]]; then
  pir_print_resolved_profile
  printf 'status=prepared-only\n'
  exit 0
fi

pir_prepare_local_paths
exec 9>"$PIR_LOG_DIR/paper-v1.execution.lock"
flock -n 9 || pir_die "another paper-v1 build/run currently owns the shared binary"

pir_build_cell "$SKIP_BUILD"
if [[ "$MODE" == "--build-only" ]]; then
  pir_print_resolved_profile
  printf 'binary=%s\n' "$PIR_TEST_BINARY"
  printf 'binary_sha256=%s\n' "$(file_sha256 "$PIR_TEST_BINARY")"
  printf 'status=built-only\n'
  exit 0
fi

pir_check_runtime
pir_execute_cell "$PIR_LOG_DIR/paper-v1/$SIZE/$PREPROC_PROFILE/$RUN_ID"
