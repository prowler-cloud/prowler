<p align="center">
  <img align="center" src="docs/img/prowler-pro-dark.png#gh-dark-mode-only" width="150" height="36">
  <img align="center" src="docs/img/prowler-pro-light.png#gh-light-mode-only" width="15%" height="15%">
</p>
<p align="center">
  <b><i>&nbsp&nbsp&nbsp See all the things you and your team can do with ProwlerPro at <a href="https://prowler.pro">prowler.pro</a></i></b>
</p>
<hr>
<p align="center">
  <img src="https://user-images.githubusercontent.com/3985464/113734260-7ba06900-96fb-11eb-82bc-d4f68a1e2710.png" />
</p>
<p align="center">
  <a href="https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog"><img alt="Slack Shield" src="https://img.shields.io/badge/slack-prowler-brightgreen.svg?logo=slack"></a>
  <a href="https://pypi.org/project/prowler-cloud/"><img alt="Python Version" src="https://img.shields.io/pypi/v/prowler-cloud.svg"></a>
  <a href="https://pypi.python.org/pypi/prowler-cloud/"><img alt="Python Version" src="https://img.shields.io/pypi/pyversions/prowler-cloud.svg"></a>
  <a href="https://hub.docker.com/r/toniblyx/prowler"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/toniblyx/prowler"></a>
  <a href="https://hub.docker.com/r/toniblyx/prowler"><img alt="Docker" src="https://img.shields.io/docker/cloud/build/toniblyx/prowler"></a>
  <a href="https://hub.docker.com/r/toniblyx/prowler"><img alt="Docker" src="https://img.shields.io/docker/image-size/toniblyx/prowler"></a>
  <a href="https://gallery.ecr.aws/o4g1s5r6/prowler"><img width="120" height=19" alt="AWS ECR Gallery" src="https://user-images.githubusercontent.com/3985464/151531396-b6535a68-c907-44eb-95a1-a09508178616.png"></a>
</p>
<p align="center">
  <a href="https://github.com/prowler-cloud/prowler"><img alt="Repo size" src="https://img.shields.io/github/repo-size/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler/issues"><img alt="Issues" src="https://img.shields.io/github/issues/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler/releases"><img alt="Version" src="https://img.shields.io/github/v/release/prowler-cloud/prowler?include_prereleases"></a>
  <a href="https://github.com/prowler-cloud/prowler/releases"><img alt="Version" src="https://img.shields.io/github/release-date/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="Contributors" src="https://img.shields.io/github/contributors-anon/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="License" src="https://img.shields.io/github/license/prowler-cloud/prowler"></a>
  <a href="https://twitter.com/ToniBlyx"><img alt="Twitter" src="https://img.shields.io/twitter/follow/toniblyx?style=social"></a>
</p>

# Description

`Prowler` is an Open Source security tool to perform AWS and Azure security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.

It contains hundreds of controls covering CIS, PCI-DSS, ISO27001, GDPR, HIPAA, FFIEC, SOC2, AWS FTR, ENS and custom security frameworks.

# ⚙️ Install

```console
pip install prowler-cloud
prowler -v
```

## Prowler container versions

The available versions of Prowler are the following:

- latest: in sync with master branch (bear in mind that it is not a stable version)
- <x.y.z> (release): you can find the releases [here](https://github.com/prowler-cloud/prowler/releases), those are stable releases.
- stable: this tag always point to the latest release.

The container images are available here:

- [DockerHub](https://hub.docker.com/r/toniblyx/prowler/tags)
- [AWS Public ECR](https://gallery.ecr.aws/o4g1s5r6/prowler)

# 📐✏️ High level architecture

You can run Prowler from your workstation, an EC2 instance, Fargate or any other container, Codebuild, CloudShell and Cloud9.

![Architecture](docs/img/architecture.png)

# 📝 Requirements

Prowler has been written in Python using the [AWS SDK (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html#) and [Azure SDK](https://azure.github.io/azure-sdk-for-python/).
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

  - arn:aws:iam::aws:policy/SecurityAudit
  - arn:aws:iam::aws:policy/job-function/ViewOnlyAccess

  > Moreover, some read-only additional permissions are needed for several checks, make sure you attach also the custom policy [prowler-additions-policy.json](https://github.com/prowler-cloud/prowler/blob/master/iam/prowler-additions-policy.json) to the role you are using.

  > If you want Prowler to send findings to [AWS Security Hub](https://aws.amazon.com/security-hub), make sure you also attach the custom policy [prowler-security-hub.json](https://github.com/prowler-cloud/prowler/blob/master/iam/prowler-security-hub.json).


# 💻 Basic Usage

To run prowler, you will need to specify the provider (e.g aws or azure):

```console
prowler <provider>
```

![Prowler Execution](docs/img/short-display.png)

> Running the `prowler` command without options will use your environment variable credentials.

By default, prowler will generate a CSV and a JSON report, however you could generate an HTML or an JSON-ASFF report with `-M` or `--output-modes`:

```console
prowler <provider> -M csv json json-asff html
```

You can use `-l`/`--list-checks` or `--list-services` to list all available checks or services within the provider.

```console
prowler <provider> --list-checks
prowler <provider> --list-services
```

For executing specific checks or services you can use options `-c`/`checks` or `-s`/`services`:

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

## AWS

Use a custom AWS profile with `-p`/`--profile` and/or AWS regions which you want to audit with `-f`/`--filter-region`:

```console
prowler aws --profile custom-profile -f us-east-1 eu-south-2
```
> By default, `prowler` will scan all AWS regions.

# 🎉 New Features

- Multi-cloud support!

# 📖 Documentation

The full documentation can be found here:

[https://prowler-cloud.github.io/prowler/](https://prowler-cloud.github.io/prowler/)
# 📃 License

Prowler is licensed as Apache License 2.0 as specified in each file. You may obtain a copy of the License at
<http://www.apache.org/licenses/LICENSE-2.0>
