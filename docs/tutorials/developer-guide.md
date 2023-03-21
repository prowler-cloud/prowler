# Developer Guide

You can extend Prowler in many different ways, in most cases you will want to create your own checks and compliance security frameworks, here is where you can learn about how to get started with it. We also include how to create custom outputs, integrations and more.

## Get the code and install all dependencies

First of all, you need a version of Python 3.9 or higher and also pip installed to be able to install all dependencies requred. Once that is satisfied go a head and clone the repo:

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

This repo has git pre-commit hooks managed via the pre-commit tool. Install it how ever you like, then in the root of this repo run:
```
pre-commit install
```
You should get an output like the following:
```
pre-commit installed at .git/hooks/pre-commit
```

Before we merge any of your pull requests we pass checks to the code, we use the following tools and automation to make sure the code is secure and dependencies up-to-dated (these should have been already installed if you ran `pipenv install -d`):

- `bandit` for code security review.
- `safety` and `dependabot` for dependencies.
- `hadolint` and `dockle` for our containers security.
- `snyk` in Docker Hub.
- `clair` in Amazon ECR.
- `vulture`, `flake8`, `black` and `pylint` for formatting and best practices.

You can see all dependencies in file `Pipfile`.

## Create a new check for a Provider

### If the check you want to create belongs to an existing service:

### If the check you want to create belongs to a service not supported already by Prowler you will need to create a new service first:

## Create a new security compliance framework

If you want to create or contribute with your own security frameworks or add public ones to Prowler you need to make sure the checks are available if not you have to create your own. Then create a compliance file per provider like in `prowler/compliance/aws/` and name it as `<framework>_<version>_<provider>.json` then follow the following format to create yours.

Each file version of a framework will have the following structure at high level with the case that each framework needs to be generally identified), one requirement can be also called one control but one requirement can be linked to multiple prowler checks.:

- `Framework`: string. Indistiguish name of the framework, like CIS
- `Provider`: string. Provider where the framework applies, such as AWS, Azure, OCI,...
- `Version`: string. Version of the framework itself, like 1.4 for CIS.
- `Requirements`: array of objects. Include all requirements or controls with the mapping to Prowler.
- `Requirements_Id`: string. Unique identifier per each requirement in the specific framework
- `Requirements_Description`: string. Description as in the framework.
- `Requirements_Attributes`: array of objects. Includes all needed attributes per each requirement, like levels, sections, etc. Whatever helps to create a dedicated report with the result of the findings. Attributes would be taken as closely as possible from the framework's own terminology directly.
- `Requirements_Checks`: array. Prowler checks that are needed to prove this requirement. It can be one or multiple checks. In case of no automation possible this can be empty.

```
{
  "Framework": "<framework>-<provider>",
  "Version": "<version>",
  "Requirements": [
    {
      "Id": "<unique-id>",
      "Description": "Requiemente full description",
      "Checks": [
        "Here is the prowler check or checks that is going to be executed"
      ],
      "Attributes": [
        {
         <Add here your custom attributes.>
        }
      ]
    }
```

Finally, to have a proper output file for your reports, your framework data model has to be created in `prowler/lib/outputs/models.py` and also the CLI table output in `prowler/lib/outputs/compliance.py`.


## Create a custom output format

## Create a new integration

## Contribute with documentation

We use `mkdocs` to build this Prowler documentation site so you can easely contribute back with new docs or improving them.

1. Install `mkdocs` with your favorite package manager.
2. Inside the `prowler` repository folder run `mkdocs serve` and point your browser to `http://localhost:8000` and you will see live changes to your local copy of this documentation site.
3. Make all needed changes to docs or add new documents. To do so just edit existing md files inside `prowler/docs` and if you are adding a new section or file please make sure you add it to `mkdocs.yaml` file in the root folder of the Prowler repo.
4. Once you are done with changes, please send a pull request to us for review and merge. Thank you in advance!

## Want some swag as appreciation for your contribution?

If you are like us and you love swag, we are happy to thank you for your contribution with some laptop stickers or whatever other swag we may have at that time. Please, tell us more details and your pull request link in our [Slack workspace here](https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog). You can also reach out to Toni de la Fuente on Twitter [here](https://twitter.com/ToniBlyx), his DMs are open.
