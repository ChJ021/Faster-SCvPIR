#!/usr/bin/env bash

# Run only the targeted BFV parameter validation; this never starts PIR E2E.

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly TEST_SOURCE="$PIR_UPSTREAM_DIR/hintless_simplepir/new_pir_test.cc"
readonly TEST_TARGET="//linpir:bfv_parameters_test"
readonly RUNS="${PIR_BFV_TEST_RUNS:-1}"

[[ "$RUNS" =~ ^[1-9][0-9]*$ ]] \
  || pir_die "PIR_BFV_TEST_RUNS must be a positive integer"
grep -Eq '\.qs[[:space:]]*=[[:space:]]*\{19988226643746817ULL,[[:space:]]*19988226643402753ULL\}' "$TEST_SOURCE" \
  || pir_die "new_pir_test.cc does not contain the validated BFV moduli"
grep -Eq '\.gadget_log_bs[[:space:]]*=[[:space:]]*\{13,[[:space:]]*14\}' "$TEST_SOURCE" \
  || pir_die "new_pir_test.cc does not contain the validated gadget bases"

pir_prepare_compiler
pir_resolve_bazel

test_log="$(mktemp -t small-client-bfv-test.XXXXXX)"
trap 'rm -f -- "$test_log"' EXIT

cd "$PIR_UPSTREAM_DIR"
if "${PIR_BAZEL_COMMAND[@]}" "${PIR_BAZEL_STARTUP_FLAGS[@]}" test \
    "${PIR_BAZEL_ACTION_FLAGS[@]}" \
    --cache_test_results=no \
    "--runs_per_test=$RUNS" \
    --test_output=all \
    "$TEST_TARGET" >"$test_log" 2>&1; then
  awk '
    function field(name,    i, parts) {
      for (i = 1; i <= NF; ++i) {
        split($i, parts, "=")
        if (parts[1] == name) {
          return parts[2]
        }
      }
      return ""
    }
    /\[BFV_VALIDATION\].*Q_bits=/ {
      parameter_line = $0
    }
    /\[BFV_VALIDATION\].*max_noise_bits=/ {
      max_noise = field("max_noise_bits") + 0
      rms_noise = field("rms_noise_bits") + 0
      margin = field("margin_bits") + 0
      threshold = field("threshold_bits") + 0
      overflow = field("noise_overflow")
      if (noise_count == 0 || max_noise > worst_max_noise) {
        worst_max_noise = max_noise
      }
      if (noise_count == 0 || rms_noise > worst_rms_noise) {
        worst_rms_noise = rms_noise
      }
      if (noise_count == 0 || margin < minimum_margin) {
        minimum_margin = margin
      }
      ++noise_count
    }
    /\[BFV_VALIDATION\].*gaussian_model_log2_failure<=/ {
      for (i = 1; i <= NF; ++i) {
        if (index($i, "gaussian_model_log2_failure<=") == 1) {
          probability = $i
          sub(/^gaussian_model_log2_failure<=/, "", probability)
          probability += 0
        }
      }
      target = field("target") + 0
      confidence = field("variance_confidence_bits") + 0
      model = field("model")
      if (probability_count == 0 || probability > worst_probability) {
        worst_probability = probability
      }
      ++probability_count
    }
    END {
      if (parameter_line == "" || noise_count == 0 ||
          probability_count == 0) {
        exit 2
      }
      print parameter_line
      printf "[BFV_VALIDATION] worst_max_noise_bits=%.2f " \
             "worst_rms_noise_bits=%.2f threshold_bits=%.2f " \
             "minimum_margin_bits=%.2f noise_overflow=%s\n", \
             worst_max_noise, worst_rms_noise, threshold, minimum_margin, \
             overflow
      printf "[BFV_VALIDATION] worst_gaussian_model_log2_failure<=%.2f " \
             "target=%.2f variance_confidence_bits=%.2f model=%s\n", \
             worst_probability, target, confidence, model
    }
  ' "$test_log"
  printf '[BFV_VALIDATION] runs=%s targeted_test=PASS end_to_end=NOT_RUN\n' "$RUNS"
else
  grep '\[BFV_VALIDATION\]' "$test_log" | tail -n 3 || true
  printf '[BFV_VALIDATION] runs=%s targeted_test=FAIL end_to_end=NOT_RUN\n' "$RUNS" >&2
  tail -n 40 "$test_log" >&2
  exit 1
fi
