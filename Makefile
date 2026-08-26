UV ?= uv
UV_FLAGS ?= --cache-dir .uv-cache --offline
PYTHON_VERSION ?= 3.12
VENV_PYTHON := .venv/bin/python
UV_RUN := $(UV) $(UV_FLAGS) run --python $(VENV_PYTHON)

.PHONY: venv check test demo benchmark benchmark-via native-verify native-build native-list-tests native-smoke native-env

venv:
	$(UV) $(UV_FLAGS) venv --allow-existing --python $(PYTHON_VERSION) .venv

check: venv test
	$(UV_RUN) python -m compileall -q small_client_vpir tests

test: venv
	$(UV_RUN) python -m unittest discover -s tests -v

demo: venv
	$(UV_RUN) python -m small_client_vpir demo

benchmark: venv
	$(UV_RUN) python -m small_client_vpir benchmark --protocol small-client --rows 8 --columns 32 --queries 3

benchmark-via: venv
	$(UV_RUN) python -m small_client_vpir benchmark --protocol via --rows 8 --columns 32 --queries 3

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
