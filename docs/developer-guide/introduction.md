# Introduction to developing in Prowler

Extending Prowler

Prowler can be extended in various ways, with common use cases including:

- New security checks
- New compliance frameworks
- New output formats
- New integrations
- New proposed features

All the relevant information for these cases is included in this guide.

## Getting the Code and Installing All Dependencies

### Prerequisites

Before proceeding, ensure the following:

- Git is installed.
- Python 3.9 or higher is installed.
- `poetry` is installed to manage dependencies.

### Forking the Prowler Repository

To contribute to Prowler, fork the Prowler GitHub repository. This allows you to propose changes, submit new features, and fix bugs. For guidance on forking, refer to the [official GitHub documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo?tool=webui#forking-a-repository).

### Cloning Your Forked Repository

Once your fork is created, clone it using the following commands:

```
git clone https://github.com/<your-github-user>/prowler
cd prowler
```

### Dependency Management and Environment Isolation

To prevent conflicts between environments, we recommend using `poetry`, a Python dependency management solution. Install it by following the [instructions](https://python-poetry.org/docs/#installation).

### Installing Dependencies

To install all required dependencies, including those needed for development, run:

```
poetry install --with dev
eval $(poetry env activate)
```

???+ important
    Starting from Poetry v2.0.0, `poetry shell` has been deprecated in favor of `poetry env activate`.
    If your poetry version is below 2.0.0 you must keep using `poetry shell` to activate your environment.
    In case you have any doubts, consult the [Poetry environment activation guide](https://python-poetry.org/docs/managing-environments/#activating-the-environment).

## Contributing to Prowler

### Ways to Contribute

Here are some ideas for collaborating with Prowler:

1. **Review Current Issues**: Check out our [GitHub Issues](https://github.com/prowler-cloud/prowler/issues) page. We often tag issues as `good first issue` - these are perfect for new contributors as they are typically well-defined and manageable in scope.

2. **Expand Prowler's Capabilities**: Prowler is constantly evolving, and you can be a part of its growth. Whether you are adding checks, supporting new services, or introducing integrations, your contributions help improve the tool for everyone. Here is how you can get involved:

    - **Adding New Checks**
    Want to improve Prowler's detection capabilities for your favorite cloud provider? You can contribute by writing new checks. To get started, follow the [create a new check guide](./checks.md).

    - **Adding New Services**
    One key service for your favorite cloud provider is missing? Add it to Prowler! To add a new service, check out the [create a new service guide](./services.md). Do not forget to include relevant checks to validate functionality.

    - **Adding New Providers**
    If you would like to extend Prowler to work with a new cloud provider, follow the [create a new provider guide](./provider.md). This typically involves setting up new services and checks to ensure compatibility.

    - **Adding New Output Formats**
    Want to tailor how results are displayed or exported? You can add custom output formats by following the [create a new output format guide](./outputs.md).

    - **Adding New Integrations**
    Prowler can work with other tools and platforms through integrations. If you would like to add one, see the [create a new integration guide](./integrations.md).

    - **Proposing or Implementing Features**
    Got an idea to make Prowler better? Whether it is a brand-new feature or an enhancement to an existing one, you are welcome to propose it or help implement community-requested improvements.

3. **Improve Documentation**: Help make Prowler more accessible by enhancing our documentation, fixing typos, or adding examples/tutorials. See the tutorial of how we write our documentation [here](./documentation.md).

4. **Bug Fixes**: If you find any issues or bugs, you can report them in the [GitHub Issues](https://github.com/prowler-cloud/prowler/issues) page and if you want you can also fix them.

Remember, our community is here to help! If you need guidance, do not hesitate to ask questions in the issues or join our [Slack workspace](https://goto.prowler.com/slack).

### Pre-Commit Hooks

This repository uses Git pre-commit hooks managed by the [pre-commit](https://pre-commit.com/) tool, it is installed with `poetry install --with dev`. Next, run the following command in the root of this repository:

```shell
pre-commit install
```

Successful installation should produce the following output:

```shell
pre-commit installed at .git/hooks/pre-commit
```

### Code Quality and Security Checks

Before merging pull requests, several automated checks and utilities ensure code security and updated dependencies:

???+ note
    These should have been already installed if `poetry install --with dev` was already run.

- [`bandit`](https://pypi.org/project/bandit/) for code security review.
- [`safety`](https://pypi.org/project/safety/) and [`dependabot`](https://github.com/features/security) for dependencies.
- [`hadolint`](https://github.com/hadolint/hadolint) and [`dockle`](https://github.com/goodwithtech/dockle) for container security.
- [`Snyk`](https://docs.snyk.io/integrations/snyk-container-integrations/container-security-with-docker-hub-integration) for container security in Docker Hub.
- [`clair`](https://github.com/quay/clair) for container security in Amazon ECR.
- [`vulture`](https://pypi.org/project/vulture/), [`flake8`](https://pypi.org/project/flake8/), [`black`](https://pypi.org/project/black/), and [`pylint`](https://pypi.org/project/pylint/) for formatting and best practices.

Additionally, ensure the latest version of [`TruffleHog`](https://github.com/trufflesecurity/trufflehog) is installed to scan for sensitive data in the code. Follow the official [installation guide](https://github.com/trufflesecurity/trufflehog?tab=readme-ov-file#floppy_disk-installation) for setup.

### Dependency Management

All dependencies are listed in the `pyproject.toml` file.

For proper code documentation, refer to the following and follow the code documentation practices presented there: [Google Python Style Guide - Comments and Docstrings](https://github.com/google/styleguide/blob/gh-pages/pyguide.md#38-comments-and-docstrings).

???+ note
    If you encounter issues when committing to the Prowler repository, use the `--no-verify` flag with the `git commit` command.

### Repository Folder Structure

Understanding the layout of the Prowler codebase will help you quickly find where to add new features, checks, or integrations. The following is a high-level overview from the root of the repository:

```
prowler/
├── prowler/           # Main source code for Prowler SDK (CLI, providers, services, checks, compliances, config, etc.)
├── api/               # API server and related code
├── dashboard/         # Local Dashboard extracted from the CLI output
├── ui/                # Web UI components
├── util/              # Utility scripts and helpers
├── tests/             # Prowler SDK test suite
├── docs/              # Documentation, including this guide
├── examples/          # Example output formats for providers and scripts
├── permissions/       # Permission-related files and policies
├── contrib/           # Community-contributed scripts or modules
├── kubernetes/        # Kubernetes deployment files
├── .github/           # GitHub related files (workflows, issue templates, etc.)
├── pyproject.toml     # Python project configuration (Poetry)
├── poetry.lock        # Poetry lock file
├── README.md          # Project overview and getting started
├── Makefile           # Common development commands
├── Dockerfile         # SDK Docker container
├── docker-compose.yml # Prowler App Docker compose
└── ...                # Other supporting files
```

## Pull Request Checklist

When creating or reviewing a pull request in https://github.com/prowler-cloud/prowler, follow [this checklist](https://github.com/prowler-cloud/prowler/blob/master/.github/pull_request_template.md#checklist).

## Contribution Appreciation

If you enjoy swag, we’d love to thank you for your contribution with laptop stickers or other Prowler merchandise!

To request swag: Share your pull request details in our [Slack workspace](https://goto.prowler.com/slack).

You can also reach out to Toni de la Fuente on [Twitter](https://twitter.com/ToniBlyx)—his DMs are open!

# Testing a Pull Request from a Specific Branch

To test Prowler from a specific branch (for example, to try out changes from a pull request before it is merged), you can use `pipx` to install directly from GitHub:

```sh
pipx install "git+https://github.com/prowler-cloud/prowler.git@branch-name"
```

Replace `branch-name` with the name of the branch you want to test. This will install Prowler in an isolated environment, allowing you to try out the changes safely.