# Regenerate the ARM JSON template from the Bicep source. The Azure Portal
# "Deploy to Azure" deep link (`#create/Microsoft.Template/uri/<url>`) only
# accepts ARM JSON, not raw Bicep source, so the .json file is the artifact
# actually consumed by users — keep it committed and in sync with the .bicep.
#
# Requires Bicep CLI (>= 0.30 for the Microsoft.Graph extension). Install
# with `az bicep install` (via Azure CLI) or download the standalone binary
# from https://github.com/Azure/bicep/releases.
#
# `bicepconfig.json` in this directory registers the Microsoft.Graph
# extension against the public Microsoft Container Registry, so the CLI can
# resolve `extension microsoftGraphV1` without extra flags.

BICEP ?= bicep

.PHONY: build check clean

build: prowler-scan.json

prowler-scan.json: prowler-scan.bicep bicepconfig.json
	$(BICEP) build $<

# CI hook: fail if the JSON is out of sync with the Bicep source. Run
# `make build` locally and commit both files before opening the PR.
check: prowler-scan.bicep bicepconfig.json
	$(BICEP) build prowler-scan.bicep --outfile /tmp/prowler-scan.check.json
	diff -q prowler-scan.json /tmp/prowler-scan.check.json
	rm /tmp/prowler-scan.check.json

clean:
	rm -f prowler-scan.json
