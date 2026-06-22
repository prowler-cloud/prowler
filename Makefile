.DEFAULT_GOAL:=help

DEV_LOCAL := ./scripts/development/dev-local.sh

.PHONY: dev dev-setup dev-attach dev-launch dev-stop dev-clean dev-wipe dev-status

##@ Local Development
dev: ## Start local API, worker, and database logs
	$(DEV_LOCAL) all

dev-setup: ## Bootstrap local dependencies, migrations, and fixtures
	$(DEV_LOCAL) setup

dev-attach: ## Attach to the local tmux development session
	$(DEV_LOCAL) attach

dev-launch: ## Start the local stack on fixed ports and attach
	$(DEV_LOCAL) launch

dev-stop: ## Stop the local tmux session and containers
	$(DEV_LOCAL) kill

dev-clean: ## Remove stopped local development containers
	$(DEV_LOCAL) clean

dev-wipe: ## Stop everything and delete local development data
	$(DEV_LOCAL) wipe

dev-status: ## Show local development container status
	$(DEV_LOCAL) status

##@ Testing
test:   ## Test with pytest
	rm -rf .coverage && \
	pytest -n auto -vvv -s --cov=./prowler --cov-report=xml tests

coverage: ## Show Test Coverage
	coverage run --skip-covered -m pytest -v && \
	coverage report -m && \
	rm -rf .coverage && \
	coverage report -m

coverage-html: ## Show Test Coverage
	rm -rf ./htmlcov && \
	coverage html && \
	open htmlcov/index.html

##@ Linting
format: ## Format Code
	@echo "Running black..."
	black .

lint: ## Lint Code
	@echo "Running flake8..."
	flake8 . --ignore=E266,W503,E203,E501,W605,E128 --exclude .venv,contrib
	@echo "Running black... "
	black --check .
	@echo "Running pylint..."
	pylint --disable=W,C,R,E -j 0 prowler util

##@ PyPI
pypi-clean: ## Delete the distribution files
	rm -rf ./dist && rm -rf ./build && rm -rf prowler.egg-info

pypi-build: ## Build package
	$(MAKE) pypi-clean && \
	uv build

pypi-upload: ## Upload package
	python3 -m twine upload --repository pypi dist/*


##@ Help
help:     ## Show this help.
	@echo "Prowler Makefile"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build no cache
build-no-cache-dev:
	docker compose -f docker-compose-dev.yml build --no-cache api-dev worker-dev worker-beat mcp-server

##@ Development Environment
run-api-dev: ## Start development environment with API, PostgreSQL, Valkey, MCP, and workers
	docker compose -f docker-compose-dev.yml up api-dev postgres valkey worker-dev worker-beat mcp-server

##@ Development Environment
build-and-run-api-dev: build-no-cache-dev run-api-dev
