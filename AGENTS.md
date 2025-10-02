# Repository Guidelines

## How to Use This Guide

- Start here for cross-project norms, Prowler is a monorepo with several components. Every component should have an `AGENTS.md` file that contains the guidelines for the agents in that component. The file is located beside the code you are touching (e.g. `api/AGENTS.md`, `ui/AGENTS.md`, `prowler/AGENTS.md`).
- Follow the stricter rule when guidance conflicts; component docs override this file for their scope.
- Keep instructions synchronized. When you add new workflows or scripts, update both, the relevant component `AGENTS.md` and this file if they apply broadly.

## Project Overview

Prowler is an open-source cloud security assessment tool that supports multiple cloud providers (AWS, Azure, GCP, Kubernetes, GitHub, M365, etc.). The project consists in a monorepo with the following main components:

- **Prowler SDK**: Python SDK, includes the Prowler CLI, providers, services, checks, compliances, config, etc. (`prowler/`)
- **Prowler API**: Django-based REST API backend (`api/`)
- **Prowler UI**: Next.js frontend application (`ui/`)
- **Prowler MCP Server**: Model Context Protocol server that gives access to the entire Prowler ecosystem for LLMs (`mcp_server/`)
- **Prowler Dashboard**: Prowler CLI feature that allows to visualize the results of the scans in a simple dashboard (`dashboard/`)

### Project Structure (Key Folders & Files)

- `prowler/`: Main source code for Prowler SDK (CLI, providers, services, checks, compliances, config, etc.)
- `api/`: Django-based REST API backend components
- `ui/`: Next.js frontend application
- `mcp_server/`: Model Context Protocol server that gives access to the entire Prowler ecosystem for LLMs
- `dashboard/`: Prowler CLI feature that allows to visualize the results of the scans in a simple dashboard
- `docs/`: Documentation
- `examples/`: Example output formats for providers and scripts
- `permissions/`: Permission-related files and policies
- `contrib/`: Community-contributed scripts or modules
- `tests/`: Prowler SDK test suite
- `docker-compose.yml`: Docker compose file to run the Prowler App (API + UI) production environment
- `docker-compose-dev.yml`: Docker compose file to run the Prowler App (API + UI) development environment
- `pyproject.toml`: Poetry Prowler SDK project file
- `.pre-commit-config.yaml`: Pre-commit hooks configuration
- `Makefile`: Makefile to run the project
- `LICENSE`: License file
- `README.md`: README file
- `CONTRIBUTING.md`: Contributing guide

## Python Development

Most of the code is written in Python, so the main files in the root are focused on Python code.

### Poetry Dev Environment

For developing in Python we recommend using `poetry` to manage the dependencies. The minimal version is `2.1.1`. So it is recommended to run all commands using `poetry run ...`.

To install the core dependencies to develop it is needed to run `poetry install --with dev`.

### Pre-commit hooks

The project has pre-commit hooks to lint and format the code. They are installed by running `poetry run pre-commit install`.

When commiting a change, the hooks will be run automatically. Some of them are:

- Code formatting (black, isort)
- Linting (flake8, pylint)
- Security checks (bandit, safety, trufflehog)
- YAML/JSON validation
- Poetry lock file validation


### Linting and Formatting

We use the following tools to lint and format the code:

- `flake8`: for linting the code
- `black`: for formatting the code
- `pylint`: for linting the code

You can run all using the `make` command:
```bash
poetry run make lint
poetry run make format
```

Or they will be run automatically when you commit your changes using pre-commit hooks.

## Commit & Pull Request Guidelines

For the commit messages and pull requests name follow the conventional-commit style.

Befire creating a pull request, complete the checklist in `.github/pull_request_template.md`. Summaries should explain deployment impact, highlight review steps, and note changelog or permission updates. Run all relevant tests and linters before requesting review and link screenshots for UI or dashboard changes.

### Conventional Commit Style

The Conventional Commits specification is a lightweight convention on top of commit messages. It provides an easy set of rules for creating an explicit commit history; which makes it easier to write automated tools on top of.

The commit message should be structured as follows:

```
<type>[optional scope]: <description>
<BLANK LINE>
[optional body]
<BLANK LINE>
[optional footer(s)]
```

Any line of the commit message cannot be longer 100 characters! This allows the message to be easier to read on GitHub as well as in various git tools

#### Commit Types

- **feat**: code change introuce new functionality to the application
- **fix**: code change that solve a bug in the codebase
- **docs**: documentation only changes
- **chore**: changes related to the build process or auxiliary tools and libraries, that do not affect the application's functionality
- **perf**: code change that improves performance
- **refactor**: code change that neither fixes a bug nor adds a feature
- **style**: changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
- **test**: adding missing tests or correcting existing tests
