.DEFAULT_GOAL:=help

test:   ## Test with pytest
	pytest -n auto -vvv -s

coverage: ## Show Test Coverage
	coverage run --skip-covered -m pytest -v && \
	coverage report -m && \
	rm -rf .coverage
##@ Help
help:     ## Show this help.
	@echo "Prowler Makefile"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
