<p align="center">
  <img align="center" src="https://github.com/prowler-cloud/prowler/blob/master/docs/img/prowler-logo-black.png#gh-light-mode-only" width="50%" height="50%">
  <img align="center" src="https://github.com/prowler-cloud/prowler/blob/master/docs/img/prowler-logo-white.png#gh-dark-mode-only" width="50%" height="50%">
</p>
<p align="center">
  <b><i>Prowler Open Source</b> is as dynamic and adaptable as the environment it secures. It is trusted by the industry leaders to uphold the highest standards in security.
</p>
<p align="center">
<b>Learn more at <a href="https://prowler.com">prowler.com</i></b>
</p>

<p align="center">
<a href="https://goto.prowler.com/slack"><img width="30" height="30" alt="Prowler community on Slack" src="https://github.com/prowler-cloud/prowler/assets/38561120/3c8b4ec5-6849-41a5-b5e1-52bbb94af73a"></a>
  <br>
  <a href="https://goto.prowler.com/slack">Join our Prowler community!</a>
</p>
<hr>
<p align="center">
  <a href="https://goto.prowler.com/slack"><img alt="Slack Shield" src="https://img.shields.io/badge/slack-prowler-brightgreen.svg?logo=slack"></a>
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
  <a href="https://github.com/prowler-cloud/prowler/releases"><img alt="Version" src="https://img.shields.io/github/v/release/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler/releases"><img alt="Version" src="https://img.shields.io/github/release-date/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="Contributors" src="https://img.shields.io/github/contributors-anon/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="License" src="https://img.shields.io/github/license/prowler-cloud/prowler"></a>
  <a href="https://twitter.com/ToniBlyx"><img alt="Twitter" src="https://img.shields.io/twitter/follow/toniblyx?style=social"></a>
  <a href="https://twitter.com/prowlercloud"><img alt="Twitter" src="https://img.shields.io/twitter/follow/prowlercloud?style=social"></a>
</p>
<hr>
<p align="center">
  <img align="center" src="/docs/img/prowler-cli-quick.gif" width="100%" height="100%">
</p>

# Description

**Prowler** is an open-source security tool designed to assess and enforce security best practices across AWS, Azure, Google Cloud, and Kubernetes. It supports tasks such as security audits, incident response, continuous monitoring, system hardening, forensic readiness, and remediation processes.

Prowler includes hundreds of built-in controls to ensure compliance with standards and frameworks, including:

- **Industry Standards:** CIS, NIST 800, NIST CSF, and CISA
- **Regulatory Compliance and Governance:** RBI, FedRAMP, and PCI-DSS
- **Frameworks for Sensitive Data and Privacy:** GDPR, HIPAA, and FFIEC
- **Frameworks for Organizational Governance and Quality Control:** SOC2 and GXP
- **AWS-Specific Frameworks:** AWS Foundational Technical Review (FTR) and AWS Well-Architected Framework (Security Pillar)
- **National Security Standards:** ENS (Spanish National Security Scheme)
- **Custom Security Frameworks:** Tailored to your needs

## Prowler CLI and Prowler Cloud

Prowler offers a Command Line Interface (CLI), known as Prowler Open Source, and an additional service built on top of it, called <a href="https://prowler.com">Prowler Cloud</a>.

## Prowler App

Prowler App is a web-based application that simplifies running Prowler across your cloud provider accounts. It provides a user-friendly interface to visualize the results and streamline your security assessments.

![Prowler App](docs/img/overview.png)

>For more details, refer to the [Prowler App Documentation](https://docs.prowler.com/projects/prowler-open-source/en/latest/#prowler-app-installation)

## Prowler CLI

```console
prowler <provider>
```
![Prowler CLI Execution](docs/img/short-display.png)


## Prowler Dashboard

```console
prowler dashboard
```
![Prowler Dashboard](docs/img/dashboard.png)

# Prowler at a Glance

| Provider | Checks | Services | [Compliance Frameworks](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/compliance/) | [Categories](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/misc/#categories) |
|---|---|---|---|---|
| AWS | 564 | 82 | 33 | 10 |
| GCP | 79 | 13 | 7 | 3 |
| Azure | 140 | 18 | 8 | 3 |
| Kubernetes | 83 | 7 | 4 | 7 |
| M365 | 44 | 2 | 2 | 0 |
| NHN (Unofficial) | 6 | 2 | 1 | 0 |

> Use the following commands to list Prowler's available checks, services, compliance frameworks, and categories: `prowler <provider> --list-checks`, `prowler <provider> --list-services`, `prowler <provider> --list-compliance` and `prowler <provider> --list-categories`.

# 💻 Installation

## Prowler App

Installing Prowler App
Prowler App offers flexible installation methods tailored to various environments:

> For detailed instructions on using Prowler App, refer to the [Prowler App Usage Guide](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app/).

### Docker Compose

**Requirements**

* `Docker Compose` installed: https://docs.docker.com/compose/install/.

**Commands**

``` console
curl -LO https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/docker-compose.yml
curl -LO https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/.env
docker compose up -d
```

> Containers are built for `linux/amd64`.

### Configuring Your Workstation for Prowler App

If your workstation's architecture is incompatible, you can resolve this by:

- **Setting the environment variable**: `DOCKER_DEFAULT_PLATFORM=linux/amd64`
- **Using the following flag in your Docker command**: `--platform linux/amd64`

> Once configured, access the Prowler App at http://localhost:3000. Sign up using your email and password to get started.

### From GitHub

**Requirements**

* `git` installed.
* `poetry` v2 installed: [poetry installation](https://python-poetry.org/docs/#installation).
* `npm` installed: [npm installation](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).
* `Docker Compose` installed: https://docs.docker.com/compose/install/.

**Commands to run the API**

``` console
git clone https://github.com/prowler-cloud/prowler
cd prowler/api
poetry install
eval $(poetry env activate)
set -a
source .env
docker compose up postgres valkey -d
cd src/backend
python manage.py migrate --database admin
gunicorn -c config/guniconf.py config.wsgi:application
```
> [!IMPORTANT]
> As of Poetry v2.0.0, the `poetry shell` command has been deprecated. Use `poetry env activate` instead for environment activation.
>
> If your Poetry version is below v2.0.0, continue using `poetry shell` to activate your environment.
> For further guidance, refer to the Poetry Environment Activation Guide https://python-poetry.org/docs/managing-environments/#activating-the-environment.

> After completing the setup, access the API documentation at http://localhost:8080/api/v1/docs.

**Commands to run the API Worker**

``` console
git clone https://github.com/prowler-cloud/prowler
cd prowler/api
poetry install
eval $(poetry env activate)
set -a
source .env
cd src/backend
python -m celery -A config.celery worker -l info -E
```

**Commands to run the API Scheduler**

``` console
git clone https://github.com/prowler-cloud/prowler
cd prowler/api
poetry install
eval $(poetry env activate)
set -a
source .env
cd src/backend
python -m celery -A config.celery beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
```

**Commands to run the UI**

``` console
git clone https://github.com/prowler-cloud/prowler
cd prowler/ui
npm install
npm run build
npm start
```

> Once configured, access the Prowler App at http://localhost:3000. Sign up using your email and password to get started.

## Prowler CLI
### Pip package
Prowler CLI is available as a project in [PyPI](https://pypi.org/project/prowler-cloud/). Consequently, it can be installed using pip with Python >3.9.1, <3.13:

```console
pip install prowler
prowler -v
```
>For further guidance, refer to [https://docs.prowler.com](https://docs.prowler.com/projects/prowler-open-source/en/latest/#prowler-cli-installation)

### Containers

**Available Versions of Prowler CLI**

The following versions of Prowler CLI are available, depending on your requirements:

- `latest`: Synchronizes with the `master` branch. Note that this version is not stable.
- `v4-latest`: Synchronizes with the `v4` branch. Note that this version is not stable.
- `v3-latest`: Synchronizes with the `v3` branch. Note that this version is not stable.
- `<x.y.z>` (release): Stable releases corresponding to specific versions. You can find the complete list of releases [here](https://github.com/prowler-cloud/prowler/releases).
- `stable`: Always points to the latest release.
- `v4-stable`: Always points to the latest release for v4.
- `v3-stable`: Always points to the latest release for v3.

The container images are available here:
- Prowler CLI:
    - [DockerHub](https://hub.docker.com/r/toniblyx/prowler/tags)
    - [AWS Public ECR](https://gallery.ecr.aws/prowler-cloud/prowler)
- Prowler App:
    - [DockerHub - Prowler UI](https://hub.docker.com/r/prowlercloud/prowler-ui/tags)
    - [DockerHub - Prowler API](https://hub.docker.com/r/prowlercloud/prowler-api/tags)

### From GitHub

Python >3.9.1, <3.13 is required with pip and Poetry:

``` console
git clone https://github.com/prowler-cloud/prowler
cd prowler
eval $(poetry env activate)
poetry install
python prowler-cli.py -v
```
> [!IMPORTANT]
> To clone Prowler on Windows, configure Git to support long file paths by running the following command: `git config core.longpaths true`.

> [!IMPORTANT]
> As of Poetry v2.0.0, the `poetry shell` command has been deprecated. Use `poetry env activate` instead for environment activation.
>
> If your Poetry version is below v2.0.0, continue using `poetry shell` to activate your environment.
> For further guidance, refer to the Poetry Environment Activation Guide https://python-poetry.org/docs/managing-environments/#activating-the-environment.

# ✏️ High level architecture

## Prowler App
**Prowler App** is composed of three key components:

- **Prowler UI**: A web-based interface, built with Next.js, providing a user-friendly experience for executing Prowler scans and visualizing results.
- **Prowler API**: A backend service, developed with Django REST Framework, responsible for running Prowler scans and storing the generated results.
- **Prowler SDK**: A Python SDK designed to extend the functionality of the Prowler CLI for advanced capabilities.

![Prowler App Architecture](docs/img/prowler-app-architecture.png)

## Prowler CLI

**Running Prowler**

Prowler can be executed across various environments, offering flexibility to meet your needs. It can be run from:

- Your own workstation

- A Kubernetes Job

- Google Compute Engine

- Azure Virtual Machines (VMs)

- Amazon EC2 instances

- AWS Fargate or other container platforms

- CloudShell

And many more environments.

![Architecture](docs/img/architecture.png)

# Deprecations from v3

## General
- `Allowlist` now is called `Mutelist`.
- The `--quiet` option has been deprecated. Use the `--status` flag to filter findings based on their status: PASS, FAIL, or MANUAL.
- All findings with an `INFO` status have been reclassified as `MANUAL`.
- The CSV output format is standardized across all providers.

**Deprecated Output Formats**

The following formats are now deprecated:
- Native JSON has been replaced with JSON in [OCSF] v1.1.0 format, which is standardized across all providers (https://schema.ocsf.io/).

## AWS

**AWS Flag Deprecation**

The flag --sts-endpoint-region has been deprecated due to the adoption of AWS STS regional tokens.

**Sending FAIL Results to AWS Security Hub**

- To send only FAILS to AWS Security Hub, use one of the following options: `--send-sh-only-fails` or `--security-hub --status FAIL`.


# 📖 Documentation

**Documentation Resources**

For installation instructions, usage details, tutorials, and the Developer Guide, visit https://docs.prowler.com/

# 📃 License

**Prowler License Information**

Prowler is licensed under the Apache License 2.0, as indicated in each file within the repository. Obtaining a Copy of the License

A copy of the License is available at <http://www.apache.org/licenses/LICENSE-2.0>
