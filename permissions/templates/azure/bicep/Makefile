# Regenerate the ARM JSON template from the Bicep source. The Azure Portal
# "Deploy to Azure" deep link (`#create/Microsoft.Template/uri/<url>`) only
# accepts ARM JSON, not raw Bicep source, so the .json file is the artifact
# actually consumed by users — keep it committed and in sync with the .bicep.
#
# Defaults to the standalone Bicep CLI. Set `BICEP=az bicep` to use the
# Azure CLI wrapper installed by `az bicep install`.

BICEP ?= bicep
BICEP_BUILD := $(BICEP) build

ifeq ($(strip $(BICEP)),az bicep)
BICEP_BUILD += --file
endif

.PHONY: build check clean sync-docs

build: prowler-scan.json sync-docs

prowler-scan.json: prowler-scan.bicep
	$(BICEP_BUILD) $<

sync-docs: prowler-scan.json
	python3 sync_docs_template.py --sync

# CI hook: fail if the JSON is out of sync with the Bicep source. Run
# `make build` locally and commit both files before opening the PR.
check: prowler-scan.bicep
	@set -eu; \
	tmp=$$(mktemp); \
	trap 'rm -f "$$tmp"' EXIT; \
	$(BICEP_BUILD) prowler-scan.bicep --outfile "$$tmp"; \
	python3 -c 'from pathlib import Path; import sys; path = Path(sys.argv[1]); path.write_bytes(path.read_bytes().rstrip(b"\r\n") + b"\n")' "$$tmp"; \
	diff -q prowler-scan.json "$$tmp"; \
	python3 sync_docs_template.py --check

clean:
	rm -f prowler-scan.json
