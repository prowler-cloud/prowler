<p align="center">
  <img align="center" src="https://github.com/prowler-cloud/prowler/blob/master/docs/img/prowler-logo-black.png?raw=True#gh-light-mode-only" width="350" height="115">
  <img align="center" src="https://github.com/prowler-cloud/prowler/blob/master/docs/img/prowler-logo-white.png?raw=True#gh-dark-mode-only" width="350" height="115">
</p>
<p align="center">
  <b><i>Prowler SaaS </b> and <b>Prowler Open Source</b> are as dynamic and adaptable as the environment they’re meant to protect. Trusted by the leaders in security.
</p>
<p align="center">
<b>Learn more at <a href="https://prowler.com">prowler.com</i></b>
</p>

<p align="center">
<a href="https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog"><img width="30" height="30" alt="Prowler community on Slack" src="https://github.com/prowler-cloud/prowler/assets/3985464/3617e470-670c-47c9-9794-ce895ebdb627"></a>
  <br>
<a href="https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog">Join our Prowler community!</a>
</p>

<hr>
<p align="center">
  <a href="https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog"><img alt="Slack Shield" src="https://img.shields.io/badge/slack-prowler-brightgreen.svg?logo=slack"></a>
  <a href="https://pypi.org/project/prowler/"><img alt="Python Version" src="https://img.shields.io/pypi/v/prowler.svg"></a>
  <a href="https://pypi.python.org/pypi/prowler/"><img alt="Python Version" src="https://img.shields.io/pypi/pyversions/prowler.svg"></a>
  <a href="https://pypistats.org/packages/prowler"><img alt="PyPI Prowler Downloads" src="https://img.shields.io/pypi/dw/prowler.svg?label=prowler%20downloads"></a>
  <a href="https://hub.docker.com/r/toniblyx/prowler"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/toniblyx/prowler"></a>
  <a href="https://hub.docker.com/r/toniblyx/prowler"><img alt="Docker" src="https://img.shields.io/docker/cloud/build/toniblyx/prowler"></a>
  <a href="https://hub.docker.com/r/toniblyx/prowler"><img alt="Docker" src="https://img.shields.io/docker/image-size/toniblyx/prowler"></a>
  <a href="https://gallery.ecr.aws/prowler-cloud/prowler"><img width="120" height=19" alt="AWS ECR Gallery" src="https://user-images.githubusercontent.com/3985464/151531396-b6535a68-c907-44eb-95a1-a09508178616.png"></a>
  <a href="https://codecov.io/gh/prowler-cloud/prowler"><img src="https://codecov.io/gh/prowler-cloud/prowler/graph/badge.svg?token=OflBGsdpDl"/></a>
</p>
<p align="center">
  <a href="https://github.com/prowler-cloud/prowler"><img alt="Repo size" src="https://img.shields.io/github/repo-size/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler/issues"><img alt="Issues" src="https://img.shields.io/github/issues/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler/releases"><img alt="Version" src="https://img.shields.io/github/v/release/prowler-cloud/prowler?include_prereleases"></a>
  <a href="https://github.com/prowler-cloud/prowler/releases"><img alt="Version" src="https://img.shields.io/github/release-date/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="Contributors" src="https://img.shields.io/github/contributors-anon/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="License" src="https://img.shields.io/github/license/prowler-cloud/prowler"></a>
  <a href="https://twitter.com/ToniBlyx"><img alt="Twitter" src="https://img.shields.io/twitter/follow/toniblyx?style=social"></a>
  <a href="https://twitter.com/prowlercloud"><img alt="Twitter" src="https://img.shields.io/twitter/follow/prowlercloud?style=social"></a>
</p>
<hr>

# Description

`Prowler` is an Open Source security tool to perform AWS, GCP and Azure security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.

It contains hundreds of controls covering CIS, NIST 800, NIST CSF, CISA, RBI, FedRAMP, PCI-DSS, GDPR, HIPAA, FFIEC, SOC2, GXP, AWS Well-Architected Framework Security Pillar, AWS Foundational Technical Review (FTR), ENS (Spanish National Security Scheme) and your custom security frameworks.

| Provider | Checks | Services | [Compliance Frameworks](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/compliance/) | [Categories](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/misc/#categories) |
|---|---|---|---|---|
| AWS | 302 | 61 -> `prowler aws --list-services` | 27 -> `prowler aws --list-compliance` | 6 -> `prowler aws --list-categories` |
| GCP | 73 | 11 -> `prowler gcp --list-services` | 1 -> `prowler gcp --list-compliance` | 2 -> `prowler gcp --list-categories`|
| Azure | 37 | 4 -> `prowler azure --list-services` | CIS soon | 1 -> `prowler azure --list-categories` |
| Kubernetes | 83 | 7 -> `prowler kubernetes --list-services` | CIS soon | 7 -> `prowler kubernetes --list-categories` |

# 📖 Documentation

The full documentation can now be found at [https://docs.prowler.com](https://docs.prowler.com/projects/prowler-open-source/en/latest/)

## Looking for Prowler v2 documentation?
For Prowler v2 Documentation, please go to https://github.com/prowler-cloud/prowler/tree/2.12.1.

# ⚙️ Install

## Pip package
Prowler is available as a project in [PyPI](https://pypi.org/project/prowler-cloud/), thus can be installed using pip with Python >= 3.9, < 3.13:

```console
pip install prowler
prowler -v
```
More details at [https://docs.prowler.com](https://docs.prowler.com/projects/prowler-open-source/en/latest/)

## Containers

The available versions of Prowler are the following:

- `latest`: in sync with master branch (bear in mind that it is not a stable version)
- `<x.y.z>` (release): you can find the releases [here](https://github.com/prowler-cloud/prowler/releases), those are stable releases.
- `stable`: this tag always point to the latest release.

The container images are available here:

- [DockerHub](https://hub.docker.com/r/toniblyx/prowler/tags)
- [AWS Public ECR](https://gallery.ecr.aws/prowler-cloud/prowler)

## From Github

Python >= 3.9, < 3.13 is required with pip and poetry:

```
git clone https://github.com/prowler-cloud/prowler
cd prowler
poetry shell
poetry install
python prowler.py -v
```

# 📐✏️ High level architecture

You can run Prowler from your workstation, an EC2 instance, Fargate or any other container, Codebuild, CloudShell and Cloud9.

![Architecture](https://github.com/prowler-cloud/prowler/assets/38561120/bc89f7a6-c511-4337-830a-4ace8db9b911)

# 📝 Requirements

Prowler has been written in Python using the [AWS SDK (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html#), [Azure SDK](https://azure.github.io/azure-sdk-for-python/) and [GCP API Python Client](https://github.com/googleapis/google-api-python-client/).
## AWS

Since Prowler uses AWS Credentials under the hood, you can follow any authentication method as described [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-precedence).
Make sure you have properly configured your AWS-CLI with a valid Access Key and Region or declare AWS variables properly (or instance profile/role):

  ```console
  aws configure
  ```

  or

  ```console
  export AWS_ACCESS_KEY_ID="ASXXXXXXX"
  export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
  export AWS_SESSION_TOKEN="XXXXXXXXX"
  ```

Those credentials must be associated to a user or role with proper permissions to do all checks. To make sure, add the following AWS managed policies to the user or role being used:

  - `arn:aws:iam::aws:policy/SecurityAudit`
  - `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

  > Moreover, some read-only additional permissions are needed for several checks, make sure you attach also the custom policy [prowler-additions-policy.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-additions-policy.json) to the role you are using.

  > If you want Prowler to send findings to [AWS Security Hub](https://aws.amazon.com/security-hub), make sure you also attach the custom policy [prowler-security-hub.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-security-hub.json).

  ## Azure

  Prowler for Azure supports the following authentication types:

- Service principal authentication by environment variables (Enterprise Application)
- Current az cli credentials stored
- Interactive browser authentication
- Managed identity authentication

### Service Principal authentication

To allow Prowler assume the service principal identity to start the scan, it is needed to configure the following environment variables:

```console
export AZURE_CLIENT_ID="XXXXXXXXX"
export AZURE_TENANT_ID="XXXXXXXXX"
export AZURE_CLIENT_SECRET="XXXXXXX"
```

If you try to execute Prowler with the `--sp-env-auth` flag and those variables are empty or not exported, the execution is going to fail.
### AZ CLI / Browser / Managed Identity authentication

The other three cases do not need additional configuration, `--az-cli-auth` and `--managed-identity-auth` are automated options, `--browser-auth` needs the user to authenticate using the default browser to start the scan. Also `--browser-auth` needs the tenant id to be specified with `--tenant-id`.

### Permissions

To use each one, you need to pass the proper flag to the execution. Prowler for Azure handles two types of permission scopes, which are:

- **Azure Active Directory permissions**: Used to retrieve metadata from the identity assumed by Prowler and future AAD checks (not mandatory to have access to execute the tool)
- **Subscription scope permissions**: Required to launch the checks against your resources, mandatory to launch the tool.


#### Azure Active Directory scope

Azure Active Directory (AAD) permissions required by the tool are the following:

- `Directory.Read.All`
- `Policy.Read.All`


#### Subscriptions scope

Regarding the subscription scope, Prowler by default scans all the subscriptions that is able to list, so it is required to add the following RBAC builtin roles per subscription  to the entity that is going to be assumed by the tool:

- `Security Reader`
- `Reader`


## Google Cloud Platform

Prowler will follow the same credentials search as [Google authentication libraries](https://cloud.google.com/docs/authentication/application-default-credentials#search_order):

1. [GOOGLE_APPLICATION_CREDENTIALS environment variable](https://cloud.google.com/docs/authentication/application-default-credentials#GAC)
2. [User credentials set up by using the Google Cloud CLI](https://cloud.google.com/docs/authentication/application-default-credentials#personal)
3. [The attached service account, returned by the metadata server](https://cloud.google.com/docs/authentication/application-default-credentials#attached-sa)

Those credentials must be associated to a user or service account with proper permissions to do all checks. To make sure, add the `Viewer` role to the member associated with the credentials.

> By default, `prowler` will scan all accessible GCP Projects, use flag `--project-ids` to specify the projects to be scanned.

# 💻 Basic Usage

To run prowler, you will need to specify the provider (e.g aws or azure):

```console
prowler <provider>
```

![Prowler Execution](https://github.com/prowler-cloud/prowler/blob/b91b0103ff38e66a915c8a0ed84905a07e4aae1d/docs/img/short-display.png?raw=True)

> Running the `prowler` command without options will use your environment variable credentials.

By default, prowler will generate a CSV, a JSON and a HTML report, however you can generate JSON-ASFF (only for AWS Security Hub) report with `-M` or `--output-modes`:

```console
prowler <provider> -M csv json json-asff html
```

The html report will be located in the `output` directory as the other files and it will look like:

![Prowler Execution](https://github.com/prowler-cloud/prowler/blob/62c1ce73bbcdd6b9e5ba03dfcae26dfd165defd9/docs/img/html-output.png?raw=True)

You can use `-l`/`--list-checks` or `--list-services` to list all available checks or services within the provider.

```console
prowler <provider> --list-checks
prowler <provider> --list-services
```

For executing specific checks or services you can use options `-c`/`--checks` or `-s`/`--services`:

```console
prowler aws --checks s3_bucket_public_access
prowler aws --services s3 ec2
```

Also, checks and services can be excluded with options `-e`/`--excluded-checks` or `--excluded-services`:

```console
prowler aws --excluded-checks s3_bucket_public_access
prowler aws --excluded-services s3 ec2
```

You can always use `-h`/`--help` to access to the usage information and all the possible options:

```console
prowler -h
```

## Checks Configurations
Several Prowler's checks have user configurable variables that can be modified in a common **configuration file**.
This file can be found in the following path:
```
prowler/config/config.yaml
```

## AWS

Use a custom AWS profile with `-p`/`--profile` and/or AWS regions which you want to audit with `-f`/`--filter-region`:

```console
prowler aws --profile custom-profile -f us-east-1 eu-south-2
```
> By default, `prowler` will scan all AWS regions.

## Azure

With Azure you need to specify which auth method is going to be used:

```console
prowler azure [--sp-env-auth, --az-cli-auth, --browser-auth, --managed-identity-auth]
```
> By default, `prowler` will scan all Azure subscriptions.

## Google Cloud Platform

Optionally, you can provide the location of an application credential JSON file with the following argument:

```console
prowler gcp --credentials-file path
```
> By default, `prowler` will scan all accessible GCP Projects, use flag `--project-ids` to specify the projects to be scanned.

## Kubernetes

For non in-cluster execution, you can provide the location of the KubeConfig file with the following argument:

```console
prowler kubernetes --kubeconfig-file path
```

For in-cluster execution, you can use the supplied yaml to run Prowler as a job:
```console
kubectl apply -f job.yaml
kubectl apply -f prowler-role.yaml
kubectl apply -f prowler-rolebinding.yaml
kubectl get pods --> prowler-XXXXX
kubectl logs prowler-XXXXX
```

> By default, `prowler` will scan all namespaces in your active Kubernetes context, use flag `--context` to specify the context to be scanned and `--namespaces` to specify the namespaces to be scanned.

# 📃 License

Prowler is licensed as Apache License 2.0 as specified in each file. You may obtain a copy of the License at
<http://www.apache.org/licenses/LICENSE-2.0>
