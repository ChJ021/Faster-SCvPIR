.DEFAULT_GOAL := help

SIZE ?= 1gib
PROFILE ?= dense
QUERY_INDEX ?=
REPETITIONS ?=
ORDER_SEED ?=
CPU_SET ?=
SECURITY_CONFIG ?= native/security/configs/1gib.json
SECURITY_PROFILES ?= all
SECURITY_MODE ?= audit
SECURITY_METHOD ?= full

QUERY_ARG := $(if $(QUERY_INDEX),--query-index=$(QUERY_INDEX),)
CPU_ARG := $(if $(CPU_SET),--cpu-set=$(CPU_SET),)

.PHONY: help check paper-validate paper-test paper-dry-run paper-build paper-run paper-matrix paper-summarize native-verify native-build native-list-tests native-smoke native-env security-setup security-audit security-calibrate security-test security-bfv-test

help:
	@printf '%s\n' \
	  'Primary paper-v1 targets:' \
	  '  make check                 Validate manifests and run Python tests' \
	  '  make paper-dry-run         Resolve the full 5-size/4-profile matrix' \
	  '  make paper-build           Build the shared native binary' \
	  '  make paper-run SIZE=1gib PROFILE=dense' \
	  '  make paper-matrix REPETITIONS=5 ORDER_SEED=20260905 CPU_SET=2' \
	  '  make paper-summarize SESSION_ID=matrix-...' \
	  '' \
	  'Formal matrix execution requires explicit REPETITIONS and ORDER_SEED.'

check: paper-validate paper-test security-test

paper-validate:
	python3 native/experiments/paper_config.py validate

paper-test:
	python3 -m unittest discover -s native/experiments/tests -v

paper-dry-run:
	native/scripts/run-paper-matrix.sh --repetitions=1 --order-seed=20260905 --dry-run

paper-build:
	native/scripts/build-run-paper.sh --size=$(SIZE) --preproc-profile=$(PROFILE) --build-only

paper-run:
	native/scripts/build-run-paper.sh --size=$(SIZE) --preproc-profile=$(PROFILE) $(QUERY_ARG) $(CPU_ARG)

paper-matrix:
	@test -n "$(REPETITIONS)" || { printf 'error: REPETITIONS is required\n' >&2; exit 2; }
	@test -n "$(ORDER_SEED)" || { printf 'error: ORDER_SEED is required\n' >&2; exit 2; }
	@test -n "$(CPU_SET)" || { printf 'error: CPU_SET is required for a formal run\n' >&2; exit 2; }
	native/scripts/run-paper-matrix.sh --repetitions=$(REPETITIONS) --order-seed=$(ORDER_SEED) $(CPU_ARG)

paper-summarize:
	@test -n "$(SESSION_ID)" || { printf 'error: SESSION_ID is required\n' >&2; exit 2; }
	native/scripts/summarize-paper-results.sh --session-id=$(SESSION_ID)

native-verify:
	native/scripts/verify-upstream.sh

native-build:
	native/scripts/build.sh

native-list-tests:
	native/scripts/list-tests.sh

native-smoke:
	native/scripts/run-smoke.sh

native-env:
	native/scripts/capture-environment.sh

security-setup:
	native/scripts/setup-security-estimator.sh

security-audit:
	native/scripts/run-security-audit.sh --config $(SECURITY_CONFIG) --profiles $(SECURITY_PROFILES) --mode $(SECURITY_MODE) --method $(SECURITY_METHOD)

security-calibrate:
	native/scripts/run-security-calibration.sh

security-test:
	python3 -m unittest discover -s native/security/tests -v

security-bfv-test:
	native/scripts/run-bfv-parameter-test.sh
