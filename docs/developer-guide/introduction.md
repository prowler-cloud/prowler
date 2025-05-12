# Developer Guide

Extending Prowler Open Source  
Prowler can be extended in various ways, with common use cases including:  
  
Custom security checks  
  
Compliance frameworks Custom outputs and integrations  
Other options  
All the relevant information for these cases is included in this guide.

## Getting the Code and Installing All Dependencies

Prerequisites 

Before proceeding, ensure the following:  
  
- Python 3.9 or higher is installed.  
- `pip` is installed to manage dependencies.

Forking the Prowler Repository

To contribute to Prowler, fork the Prowler GitHub repository. This allows you to propose changes, submit new features, and fix bugs. For guidance on forking, refer to the [official GitHub documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo?tool=webui#forking-a-repository).

Cloning Your Forked Repository
 
Once your fork is created, clone it using the following command:

```
git clone https://github.com/<your-github-user>/prowler
cd prowler
```

Dependency Management and Environment Isolation 

To prevent conflicts between environments, we recommend using `poetry`, a Python dependency management solution. Install it by following the [instructions](https://python-poetry.org/docs/#installation).

Installing Dependencies  

To install all required dependencies, including those needed for development, run:

```
poetry install --with dev
eval $(poetry env activate) \
```

> \[!IMPORTANT] Starting from Poetry v2.0.0, `poetry shell` has been deprecated in favor of `poetry env activate`.
 
> If your Poetry version is below v2.0.0, continue using `poetry shell` to activate your environment. For further guidance, refer to the Poetry Environment Activation Guide https://python-poetry.org/docs/managing-environments/#activating-the-environment.

## Contributing to Prowler

You can contribute to Prowler with code or fixes.

Pre-Commit Hooks 

This repository uses Git pre-commit hooks managed by the [pre-commit](https://pre-commit.com/) tool. To install: follow [these](https://pre-commit.com/#install) instructions as per your preferences. Next, run the following command in the root of this repository:

```shell
pre-commit install
```

Successful installation should produce the following output:

```shell
pre-commit installed at .git/hooks/pre-commit
```

Code Quality and Security Checks  

Before merging pull requests, several automated checks and utilities ensure code security and updated dependencies: 

???+ note These should have been already installed if `poetry install --with dev` was aready run.

- [`bandit`](https://pypi.org/project/bandit/) for code security review.
- [`safety`](https://pypi.org/project/safety/) and [`dependabot`](https://github.com/features/security) for dependencies.
- [`hadolint`](https://github.com/hadolint/hadolint) and [`dockle`](https://github.com/goodwithtech/dockle) for container security.
- [`Snyk`](https://docs.snyk.io/integrations/snyk-container-integrations/container-security-with-docker-hub-integration) in Docker Hub.
- [`clair`](https://github.com/quay/clair) in Amazon ECR.
- [`vulture`](https://pypi.org/project/vulture/), [`flake8`](https://pypi.org/project/flake8/), [`black`](https://pypi.org/project/black/), and [`pylint`](https://pypi.org/project/pylint/) for formatting and best practices.

Dependency Management

All dependencies are listed in the `pyproject.toml` file.

Additionally, ensure the latest version of [`TruffleHog`](https://github.com/trufflesecurity/trufflehog) is installed to scan for sensitive data in the code. Follow the official [installation guide](https://github.com/trufflesecurity/trufflehog?tab=readme-ov-file#floppy_disk-installation) for setup.

For proper code documentation, refer to the following and follow the code documentation practices presented there: [Google Python Style Guide - Comments and Docstrings](https://github.com/google/styleguide/blob/gh-pages/pyguide.md#38-comments-and-docstrings).

???+ note If you encounter issues when committing to the Prowler repository, use the `--no-verify` flag with the `git commit` command.

## Pull Request Checklist

When creating or reviewing a pull request in https://github.com/prowler-cloud/prowler, follow this checklist:

- [ ] Review the Prowler Developer Guide. Read it here: https://docs.prowler.cloud/en/latest/developer-guide/introduction/
- [ ] Code Style Compliance: Ensure linters and formatters are installed and used. Verify adherence to the style guide: https://docs.prowler.cloud/en/latest/developer-guide/introduction/#contributing-with-your-code-or-fixes-to-prowler
- [ ] Test Coverage (Increasing or Decreasing): Check if new tests are needed to cover modifications.
- [ ] Output Changes: Carefully review modifications to Prowler outputs.
- [ ] Documentation Updates: Ensure documentation reflects introduced changes.
- [ ] Breaking Changes: Assess whether the update introduces compatibility-breaking modifications. Core Feature Modifications:  
  
Determine if the PR affects a core feature.

## Contribution Appreciation

If you enjoy swag, we’d love to thank you for your contribution with laptop stickers or other Prowler merchandise!  
  
To request swag: Share your pull request details in our [Slack workspace](https://goto.prowler.com/slack).

You can also reach out to Toni de la Fuente on [Twitter](https://twitter.com/ToniBlyx)—his DMs are open!