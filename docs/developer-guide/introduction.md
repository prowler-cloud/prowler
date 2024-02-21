# Developer Guide

You can extend Prowler Open Source in many different ways, in most cases you will want to create your own checks and compliance security frameworks, here is where you can learn about how to get started with it. We also include how to create custom outputs, integrations and more.

## Get the code and install all dependencies

First of all, you need a version of Python 3.9 or higher and also pip installed to be able to install all dependencies required. Once that is satisfied go a head and clone the repo:

```
git clone https://github.com/prowler-cloud/prowler
cd prowler
```
For isolation and avoid conflicts with other environments, we recommend usage of `poetry`:
```
pip install poetry
```
Then install all dependencies including the ones for developers:
```
poetry install
poetry shell
```

## Contributing with your code or fixes to Prowler

This repo has git pre-commit hooks managed via the [pre-commit](https://pre-commit.com/) tool. [Install](https://pre-commit.com/#install) it how ever you like, then in the root of this repo run:
```shell
pre-commit install
```
You should get an output like the following:
```shell
pre-commit installed at .git/hooks/pre-commit
```

Before we merge any of your pull requests we pass checks to the code, we use the following tools and automation to make sure the code is secure and dependencies up-to-dated (these should have been already installed if you ran `pipenv install -d`):

- [`bandit`](https://pypi.org/project/bandit/) for code security review.
- [`safety`](https://pypi.org/project/safety/) and [`dependabot`](https://github.com/features/security) for dependencies.
- [`hadolint`](https://github.com/hadolint/hadolint) and [`dockle`](https://github.com/goodwithtech/dockle) for our containers security.
- [`Snyk`](https://docs.snyk.io/integrations/snyk-container-integrations/container-security-with-docker-hub-integration) in Docker Hub.
- [`clair`](https://github.com/quay/clair) in Amazon ECR.
- [`vulture`](https://pypi.org/project/vulture/), [`flake8`](https://pypi.org/project/flake8/), [`black`](https://pypi.org/project/black/) and [`pylint`](https://pypi.org/project/pylint/) for formatting and best practices.

You can see all dependencies in file `pyproject.toml`.

## Pull Request Checklist

If you create or review a PR in https://github.com/prowler-cloud/prowler please follow this checklist:

- [ ] Make sure you've read the Prowler Developer Guide at https://docs.prowler.cloud/en/latest/developer-guide/introduction/
- [ ] Are we following the style guide, hence installed all the linters and formatters? Please check https://docs.prowler.cloud/en/latest/developer-guide/introduction/#contributing-with-your-code-or-fixes-to-prowler
- [ ] Are we increasing/decreasing the test coverage? Please, review if we need to include/modify tests for the new code.
- [ ] Are we modifying outputs? Please review it carefully.
- [ ] Do we need to modify the Prowler documentation to reflect the changes introduced?
- [ ] Are we introducing possible breaking changes? Are we modifying a core feature?


## Want some swag as appreciation for your contribution?

If you are like us and you love swag, we are happy to thank you for your contribution with some laptop stickers or whatever other swag we may have at that time. Please, tell us more details and your pull request link in our [Slack workspace here](https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog). You can also reach out to Toni de la Fuente on Twitter [here](https://twitter.com/ToniBlyx), his DMs are open.
