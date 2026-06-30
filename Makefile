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

##@ Code Quality
# `make` is the single entrypoint and mirrors CI exactly (uv run + same flags):
#   SDK (prowler/, util/) -> flake8 + black + pylint
#   API & MCP server      -> ruff (rules live in each project's pyproject.toml)
# `format` applies fixes (incl. ruff's import/upgrade autofixes); `lint` only
# verifies and is what CI gates on.
.PHONY: format format-sdk format-api format-mcp lint lint-sdk lint-api lint-mcp

format: format-sdk format-api format-mcp ## Format & autofix all components (SDK, API, MCP)

lint: lint-sdk lint-api lint-mcp ## Lint all components (SDK, API, MCP) — mirrors CI

format-sdk: ## Format SDK code (black)
	uv run black --exclude "\.venv|api|ui|skills|mcp_server" .

lint-sdk: ## Lint SDK code (flake8, black --check, pylint)
	uv run flake8 . --ignore=E266,W503,E203,E501,W605,E128 --exclude .venv,contrib,ui,api,skills,mcp_server
	uv run black --exclude "\.venv|api|ui|skills|mcp_server" --check .
	uv run pylint --disable=W,C,R,E -j 0 -rn -sn prowler/

format-api: ## Format & autofix API code (ruff)
	cd api && uv run ruff check . --exclude contrib --fix
	cd api && uv run ruff format . --exclude contrib

lint-api: ## Lint API code (ruff check + format --check)
	cd api && uv run ruff check . --exclude contrib
	cd api && uv run ruff format --check . --exclude contrib

format-mcp: ## Format & autofix MCP server code (ruff)
	cd mcp_server && uv run ruff check . --fix
	cd mcp_server && uv run ruff format .

lint-mcp: ## Lint MCP server code (ruff check + format --check)
	cd mcp_server && uv run ruff check .
	cd mcp_server && uv run ruff format --check .

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
