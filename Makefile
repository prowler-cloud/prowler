.DEFAULT_GOAL:=help

##@ Testing
test:   ## Test with pytest
 pytest -n auto -vvv -s -x
 rm -rf .coverage && \
 rm -rf ./htmlcov && \
 pytest -n auto --cov=./prowler --cov-report=xml tests

coverage: ## Show Test Coverage
 coverage run --skip-covered -m pytest -v && \
 coverage report -m && \
 rm -rf .coverage
 coverage report -m

coverage-html: ## Show Test Coverage
 coverage html && \
 open htmlcov/index.html

##@ Linting
format: ## Format Code
	@echo "Running black..."
	black .

lint: ## Lint Code
	@echo "Running flake8..."
	flake8 . --ignore=E266,W503,E203,E501,W605,E128 --exclude contrib
	@echo "Running black... "
	black --check .
	@echo "Running pylint..."
	pylint --disable=W,C,R,E -j 0 providers lib util config

##@ PyPI
pypi-clean: ## Delete the distribution files
	rm -rf ./dist && rm -rf ./build && rm -rf prowler.egg-info

pypi-build: ## Build package
	$(MAKE) pypi-clean && \
	poetry build

pypi-upload: ## Upload package
	python3 -m twine upload --repository pypi dist/*


##@ Help
help:     ## Show this help.
	@echo "Prowler Makefile"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
