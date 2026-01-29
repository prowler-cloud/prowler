<p align="center">
  <img align="center" src="https://github.com/prowler-cloud/prowler/blob/master/docs/img/prowler-logo-black.png#gh-light-mode-only" width="50%" height="50%">
  <img align="center" src="https://github.com/prowler-cloud/prowler/blob/master/docs/img/prowler-logo-white.png#gh-dark-mode-only" width="50%" height="50%">
</p>
<p align="center">
  <b><i>Prowler</b> is the Open Cloud Security platform trusted by thousands to automate security and compliance in any cloud environment. With hundreds of ready-to-use checks and compliance frameworks, Prowler delivers real-time, customizable monitoring and seamless integrations, making cloud security simple, scalable, and cost-effective for organizations of any size.
</p>
<p align="center">
<b>Secure ANY cloud at AI Speed at <a href="https://prowler.com">prowler.com</i></b>
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
  <a href="https://pypistats.org/packages/prowler"><img alt="PyPI Downloads" src="https://img.shields.io/pypi/dw/prowler.svg?label=downloads"></a>
  <a href="https://hub.docker.com/r/toniblyx/prowler"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/toniblyx/prowler"></a>
  <a href="https://gallery.ecr.aws/prowler-cloud/prowler"><img width="120" height=19" alt="AWS ECR Gallery" src="https://user-images.githubusercontent.com/3985464/151531396-b6535a68-c907-44eb-95a1-a09508178616.png"></a>
  <a href="https://codecov.io/gh/prowler-cloud/prowler"><img src="https://codecov.io/gh/prowler-cloud/prowler/graph/badge.svg?token=OflBGsdpDl"/></a>
  <a href="https://insights.linuxfoundation.org/project/prowler-cloud-prowler"><img src="https://insights.linuxfoundation.org/api/badge/health-score?project=prowler-cloud-prowler"/></a>
</p>
<p align="center">
    <a href="https://github.com/prowler-cloud/prowler/releases"><img alt="Version" src="https://img.shields.io/github/v/release/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler/releases"><img alt="Version" src="https://img.shields.io/github/release-date/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="Contributors" src="https://img.shields.io/github/contributors-anon/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler/issues"><img alt="Issues" src="https://img.shields.io/github/issues/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="License" src="https://img.shields.io/github/license/prowler-cloud/prowler"></a>
  <a href="https://twitter.com/ToniBlyx"><img alt="Twitter" src="https://img.shields.io/twitter/follow/toniblyx?style=social"></a>
  <a href="https://twitter.com/prowlercloud"><img alt="Twitter" src="https://img.shields.io/twitter/follow/prowlercloud?style=social"></a>
</p>
<hr>
<p align="center">
  <img align="center" src="/docs/img/prowler-cloud.gif" width="100%" height="100%">
</p>

# Description

**Prowler** is the world’s most widely used _open-source cloud security platform_ that automates security and compliance across **any cloud environment**. With hundreds of ready-to-use security checks, remediation guidance, and compliance frameworks, Prowler is built to _“Secure ANY cloud at AI Speed”_. Prowler delivers **AI-driven**, **customizable**, and **easy-to-use** assessments, dashboards, reports, and integrations, making cloud security **simple**, **scalable**, and **cost-effective** for organizations of any size.

Prowler includes hundreds of built-in controls to ensure compliance with standards and frameworks, including:

- **Prowler ThreatScore:** Weighted risk prioritization scoring that helps you focus on the most critical security findings first
- **Industry Standards:** CIS, NIST 800, NIST CSF, CISA, and MITRE ATT&CK
- **Regulatory Compliance and Governance:** RBI, FedRAMP, PCI-DSS, and NIS2
- **Frameworks for Sensitive Data and Privacy:** GDPR, HIPAA, and FFIEC
- **Frameworks for Organizational Governance and Quality Control:** SOC2, GXP, and ISO 27001
- **Cloud-Specific Frameworks:** AWS Foundational Technical Review (FTR), AWS Well-Architected Framework, and BSI C5
- **National Security Standards:** ENS (Spanish National Security Scheme) and KISA ISMS-P (Korean)
- **Custom Security Frameworks:** Tailored to your needs

## Prowler App / Prowler Cloud

Prowler App / [Prowler Cloud](https://cloud.prowler.com/) is a web-based application that simplifies running Prowler across your cloud provider accounts. It provides a user-friendly interface to visualize the results and streamline your security assessments.

![Prowler App](docs/images/products/overview.png)
![Risk Pipeline](docs/images/products/risk-pipeline.png)
![Threat Map](docs/images/products/threat-map.png)


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
![Prowler Dashboard](docs/images/products/dashboard.png)


## Attack Paths

Attack Paths automatically extends every completed AWS scan with a Neo4j graph that combines Cartography's cloud inventory with Prowler findings. The feature runs in the API worker after each scan and therefore requires:

- An accessible Neo4j instance (the Docker Compose files already ships a `neo4j` service).
- The following environment variables so Django and Celery can connect:

  | Variable | Description | Default |
  | --- | --- | --- |
  | `NEO4J_HOST` | Hostname used by the API containers. | `neo4j` |
  | `NEO4J_PORT` | Bolt port exposed by Neo4j. | `7687` |
  | `NEO4J_USER` / `NEO4J_PASSWORD` | Credentials with rights to create per-tenant databases. | `neo4j` / `neo4j_password` |

Every AWS provider scan will enqueue an Attack Paths ingestion job automatically. Other cloud providers will be added in future iterations.


# Prowler at a Glance
> [!Tip]
> For the most accurate and up-to-date information about checks, services, frameworks, and categories, visit [**Prowler Hub**](https://hub.prowler.com).


| Provider | Checks | Services | [Compliance Frameworks](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/compliance/) | [Categories](https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/misc/#categories) | Support | Interface |
|---|---|---|---|---|---|---|
| AWS | 584 | 84 | 40 | 17 | Official | UI, API, CLI |
| Azure | 169 | 22 | 16 | 12 | Official | UI, API, CLI |
| GCP | 100 | 17 | 14 | 7 | Official | UI, API, CLI |
| Kubernetes | 84 | 7 | 7 | 9 | Official | UI, API, CLI |
| GitHub | 20 | 2 | 1 | 2 | Official | UI, API, CLI |
| M365 | 71 | 7 | 4 | 3 | Official | UI, API, CLI |
| OCI | 52 | 14 | 1 | 12 | Official | UI, API, CLI |
| Alibaba Cloud | 64 | 9 | 2 | 9 | Official | UI, API, CLI |
| Cloudflare | 23 | 2 | 0 | 5 | Official | CLI |
| IaC | [See `trivy` docs.](https://trivy.dev/latest/docs/coverage/iac/) | N/A | N/A | N/A | Official | UI, API, CLI |
| MongoDB Atlas | 10 | 3 | 0 | 3 | Official | UI, API, CLI |
| LLM | [See `promptfoo` docs.](https://www.promptfoo.dev/docs/red-team/plugins/) | N/A | N/A | N/A | Official | CLI |
| NHN | 6 | 2 | 1 | 0 | Unofficial | CLI |

> [!Note]
> The numbers in the table are updated periodically.



> [!Note]
> Use the following commands to list Prowler's available checks, services, compliance frameworks, and categories:
> - `prowler <provider> --list-checks`
> - `prowler <provider> --list-services`
> - `prowler <provider> --list-compliance`
> - `prowler <provider> --list-categories`

# 💻 Installation

## Prowler App

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

### Common Issues with Docker Pull Installation

> [!Note]
  If you want to use AWS role assumption (e.g., with the "Connect assuming IAM Role" option), you may need to mount your local `.aws` directory into the container as a volume (e.g., `- "${HOME}/.aws:/home/prowler/.aws:ro"`). There are several ways to configure credentials for Docker containers. See the [Troubleshooting](./docs/troubleshooting.mdx) section for more details and examples.

You can find more information in the [Troubleshooting](./docs/troubleshooting.mdx) section.


### From GitHub

**Requirements**

* `git` installed.
* `poetry` v2 installed: [poetry installation](https://python-poetry.org/docs/#installation).
* `pnpm` installed: [pnpm installation](https://pnpm.io/installation).
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
pnpm install
pnpm run build
pnpm start
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
    - [DockerHub](https://hub.docker.com/r/prowlercloud/prowler/tags)
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
**Prowler App** is composed of four key components:

- **Prowler UI**: A web-based interface, built with Next.js, providing a user-friendly experience for executing Prowler scans and visualizing results.
- **Prowler API**: A backend service, developed with Django REST Framework, responsible for running Prowler scans and storing the generated results.
- **Prowler SDK**: A Python SDK designed to extend the functionality of the Prowler CLI for advanced capabilities.
- **Prowler MCP Server**: A Model Context Protocol server that provides AI tools for Lighthouse, the AI-powered security assistant. This is a critical dependency for Lighthouse functionality.

![Prowler App Architecture](docs/products/img/prowler-app-architecture.png)

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

# 🤖 AI Skills for Development

Prowler includes a comprehensive set of **AI Skills** that help AI coding assistants understand Prowler's codebase patterns and conventions.

## What are AI Skills?

Skills are structured instructions that give AI assistants the context they need to write code that follows Prowler's standards. They include:

- **Coding patterns** for each component (SDK, API, UI, MCP Server)
- **Testing conventions** (pytest, Playwright)
- **Architecture guidelines** (Clean Architecture, RLS patterns)
- **Framework-specific rules** (React 19, Next.js 15, Django DRF, Tailwind 4)

## Available Skills

| Category | Skills |
|----------|--------|
| **Generic** | `typescript`, `react-19`, `nextjs-15`, `tailwind-4`, `playwright`, `pytest`, `django-drf`, `zod-4`, `zustand-5`, `ai-sdk-5` |
| **Prowler** | `prowler`, `prowler-api`, `prowler-ui`, `prowler-mcp`, `prowler-sdk-check`, `prowler-test-ui`, `prowler-test-api`, `prowler-test-sdk`, `prowler-compliance`, `prowler-provider`, `prowler-pr`, `prowler-docs` |

## Setup

```bash
./skills/setup.sh
```

This configures skills for AI coding assistants that follow the [agentskills.io](https://agentskills.io) standard:

| Tool | Configuration |
|------|---------------|
| **Claude Code** | `.claude/skills/` (symlink) |
| **OpenCode** | `.claude/skills/` (symlink) |
| **Codex (OpenAI)** | `.codex/skills/` (symlink) |
| **GitHub Copilot** | `.github/skills/` (symlink) |
| **Gemini CLI** | `.gemini/skills/` (symlink) |

> **Note:** Restart your AI coding assistant after running setup to load the skills.
> Gemini CLI requires `experimental.skills` enabled in settings.

# 📖 Documentation

For installation instructions, usage details, tutorials, and the Developer Guide, visit https://docs.prowler.com/

# 📃 License

Prowler is licensed under the Apache License 2.0.

A copy of the License is available at <http://www.apache.org/licenses/LICENSE-2.0>
