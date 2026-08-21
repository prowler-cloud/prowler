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
	$(BICEP_BUILD) prowler-scan.bicep --outfile /tmp/prowler-scan.check.json
	diff -q prowler-scan.json /tmp/prowler-scan.check.json
	python3 sync_docs_template.py --check
	rm /tmp/prowler-scan.check.json

clean:
	rm -f prowler-scan.json
