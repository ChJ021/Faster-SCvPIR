.DEFAULT_GOAL := help

SIZE ?= 1gib
PROFILE ?= dense
QUERY_INDEX ?=
REPETITIONS ?=
ORDER_SEED ?=
CPU_SET ?=

QUERY_ARG := $(if $(QUERY_INDEX),--query-index=$(QUERY_INDEX),)
CPU_ARG := $(if $(CPU_SET),--cpu-set=$(CPU_SET),)

.PHONY: help paper-list paper-dry-run paper-build paper-run paper-matrix paper-summarize native-prepare native-env

help:
	@printf '%s\n' \
	  'Paper-v1 experiment targets:' \
	  '  make paper-list            List database sizes and preprocessing profiles' \
	  '  make paper-dry-run         Resolve the full size/profile matrix without running' \
	  '  make paper-build           Build the shared native binary' \
	  '  make paper-run SIZE=1gib PROFILE=dense' \
	  '  make paper-matrix REPETITIONS=5 ORDER_SEED=20260909 CPU_SET=2' \
	  '  make paper-summarize SESSION_ID=matrix-...' \
	  '  make native-prepare        Materialize the pinned Eigen repository' \
	  '  make native-env            Record the build environment' \
	  '' \
	  'Formal matrix execution requires REPETITIONS, ORDER_SEED and CPU_SET.'

paper-list:
	python3 experiments/paper_config.py list

paper-dry-run:
	scripts/run-paper-matrix.sh --repetitions=1 --order-seed=20260909 --dry-run

paper-build:
	scripts/build-run-paper.sh --size=$(SIZE) --preproc-profile=$(PROFILE) --build-only

paper-run:
	scripts/build-run-paper.sh --size=$(SIZE) --preproc-profile=$(PROFILE) $(QUERY_ARG) $(CPU_ARG)

paper-matrix:
	@test -n "$(REPETITIONS)" || { printf 'error: REPETITIONS is required\n' >&2; exit 2; }
	@test -n "$(ORDER_SEED)" || { printf 'error: ORDER_SEED is required\n' >&2; exit 2; }
	@test -n "$(CPU_SET)" || { printf 'error: CPU_SET is required for a formal run\n' >&2; exit 2; }
	scripts/run-paper-matrix.sh --repetitions=$(REPETITIONS) --order-seed=$(ORDER_SEED) $(CPU_ARG)

paper-summarize:
	@test -n "$(SESSION_ID)" || { printf 'error: SESSION_ID is required\n' >&2; exit 2; }
	scripts/summarize-paper-results.sh --session-id=$(SESSION_ID)

native-prepare:
	scripts/prepare-dependencies.sh

native-env:
	scripts/capture-environment.sh
