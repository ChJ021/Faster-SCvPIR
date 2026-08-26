#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

pir_verify_upstream
pir_prepare_compiler
pir_resolve_bazel

pir_print_context
printf 'source_check=passed\n'
printf 'toolchain_check=passed\n'

