#!/usr/bin/env bash

# Resolution of one experiment cell from the frozen paper-v1 manifest.
# Every database layout, memory floor and bound comes from the manifest;
# nothing here duplicates a size.

declare -gA PAPER=()

pir_load_cell_config() {
  local size_name="$1"
  local profile_name="$2"
  local config_output key value
  local -a required_keys=(
    manifest_id manifest_sha256 size profile rows columns record_bits stack_cells
    logical_bytes main_backend offline_backend main_ring_degree offline_ring_degree
    main_pad_blocks offline_pad_blocks minimum_memory_kib recommended_memory_kib
    default_query_index
  )

  [[ -f "$PIR_MANIFEST" ]] || pir_die "paper-v1 manifest is missing: $PIR_MANIFEST"
  [[ -f "$PIR_CONFIG_HELPER" ]] || pir_die "paper profile helper is missing: $PIR_CONFIG_HELPER"
  pir_require_command python3
  pir_require_command sha256sum

  config_output="$(
    python3 "$PIR_CONFIG_HELPER" --manifest "$PIR_MANIFEST" --checksum "$PIR_MANIFEST_CHECKSUM" \
      emit --size "$size_name" --profile "$profile_name"
  )" || pir_die "paper-v1 manifest validation failed"

  PAPER=()
  while IFS='=' read -r key value; do
    [[ -n "$key" ]] || continue
    PAPER["$key"]="$value"
  done <<<"$config_output"
  for key in "${required_keys[@]}"; do
    [[ -n "${PAPER[$key]:-}" ]] || pir_die "manifest helper omitted $key"
  done

  SIZE="${PAPER[size]}"
  PREPROC_PROFILE="${PAPER[profile]}"
  DB_ROWS="${PAPER[rows]}"
  DB_COLUMNS="${PAPER[columns]}"
  DB_RECORD_BITS="${PAPER[record_bits]}"
  DB_STACK_CELLS="${PAPER[stack_cells]}"
  LOGICAL_BYTES="${PAPER[logical_bytes]}"
  MAIN_PREPROC_BACKEND="${PAPER[main_backend]}"
  OFFLINE_PREPROC_BACKEND="${PAPER[offline_backend]}"
  MAIN_RING_DEGREE="${PAPER[main_ring_degree]}"
  FROZEN_OFFLINE_RING_DEGREE="${PAPER[offline_ring_degree]}"
  MAIN_PAD_BLOCK_COUNT="${PAPER[main_pad_blocks]}"
  OFFLINE_PAD_BLOCK_COUNT="${PAPER[offline_pad_blocks]}"
  MINIMUM_MEMORY_KIB="${PAPER[minimum_memory_kib]}"
  RECOMMENDED_MEMORY_KIB="${PAPER[recommended_memory_kib]}"
  MANIFEST_SHA256="${PAPER[manifest_sha256]}"
}

pir_finalize_cell_config() {
  local requested_offline_degree="$1"
  local requested_query_index="$2"

  if [[ -n "$requested_offline_degree" ]]; then
    [[ "$requested_offline_degree" == "$FROZEN_OFFLINE_RING_DEGREE" ]] \
      || pir_die "offline ring degree is frozen at $FROZEN_OFFLINE_RING_DEGREE for $SIZE/$PREPROC_PROFILE"
    [[ "$FROZEN_OFFLINE_RING_DEGREE" != "0" ]] \
      || pir_die "--offline-ring-degree is only valid for a structured offline profile"
  fi
  OFFLINE_RING_DEGREE="$FROZEN_OFFLINE_RING_DEGREE"

  QUERY_INDEX="${requested_query_index:-${PAPER[default_query_index]}}"
  [[ "$QUERY_INDEX" =~ ^[0-9]+$ ]] || pir_die "query index must be an unsigned integer"
  TOTAL_CELLS=$((DB_ROWS * DB_COLUMNS))
  ((QUERY_INDEX < TOTAL_CELLS)) || pir_die "query index is outside the configured database"
  QUERY_ROW=$((QUERY_INDEX / DB_COLUMNS))
  ((QUERY_ROW % DB_STACK_CELLS == 0)) || pir_die "query index is not aligned to the configured stack"
  ((QUERY_ROW + DB_STACK_CELLS <= DB_ROWS)) || pir_die "stacked query extends past the configured database"
}
