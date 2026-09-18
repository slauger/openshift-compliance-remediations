SHELL := /bin/bash
CHARTS := charts
SUBCHARTS := $(CHARTS)/compliance-platform $(CHARTS)/compliance-node
ALL_CHARTS := $(SUBCHARTS) $(CHARTS)/compliance-hardening
CONFIG := config/content.yaml
VENV := .venv
PY := $(VENV)/bin/python
GEN := $(VENV)/bin/compliance-remediations-gen

.PHONY: venv fetch update-sha generate docs lint lint-py test test-py deps template show-ocp-version verify clean

## Create the virtualenv and install the generator (editable).
venv:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q -e .

## Refresh the pinned sha512 for the current version (run after Renovate bumps it).
update-sha: venv
	$(GEN) --config $(CONFIG) --refresh-sha

## Download + verify + extract the pinned datastreams only.
fetch: venv
	$(GEN) --config $(CONFIG) --charts-dir $(CHARTS) --fetch-only

## Regenerate all charts + RULES.md from the datastreams.
generate: venv
	$(GEN) --config $(CONFIG) --charts-dir $(CHARTS)

## Render helm-docs READMEs (after generate).
docs:
	helm-docs --chart-search-root=$(CHARTS)

## helm lint all charts.
lint:
	@for c in $(ALL_CHARTS); do echo "== lint $$c =="; helm lint $$c || exit 1; done

## helm unittest the subcharts.
test:
	@for c in $(SUBCHARTS); do echo "== test $$c =="; helm unittest $$c || exit 1; done

## Python unit tests (parser + collisions). Depends on fetch: the datastream
## tests skip without .cache, and REQUIRE_DATASTREAM turns that skip into a
## failure so a green run never means "asserted nothing".
test-py: fetch
	REQUIRE_DATASTREAM=1 $(PY) -m unittest discover -s tests -v

## Build umbrella dependencies (pulls subcharts).
deps:
	helm dependency build $(CHARTS)/compliance-hardening

## Render the platform chart with a sample profile.
template:
	helm template compliance $(CHARTS)/compliance-platform --set profiles.ocp4-cis=true

## Suggest the live cluster's OpenShift version for targetOCPVersion.
show-ocp-version:
	@oc get clusterversion version -o jsonpath='{.status.desired.version}' 2>/dev/null \
		&& echo "" \
		|| echo "not an OpenShift cluster or no access (set targetOCPVersion manually)"

## Ruff lint the generator + tests (installs ruff via the dev extra).
lint-py: venv
	$(VENV)/bin/pip install -q -e '.[dev]'
	$(VENV)/bin/ruff check src tests

## Full pipeline: generate, docs, lint, unit tests, python tests, ruff.
verify: generate docs deps lint test test-py lint-py
	@echo "== all verification passed =="

clean:
	rm -rf $(CHARTS) .cache RULES.md
