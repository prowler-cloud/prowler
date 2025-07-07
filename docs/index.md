**Prowler** is the open source cloud security platform trusted by thousands to **automate security and compliance** in any cloud environment. With hundreds of ready-to-use checks and compliance frameworks, Prowler delivers real-time, customizable monitoring and seamless integrations, making cloud security simple, scalable, and cost-effective for organizations of any size.

The official supported providers right now are:

- **AWS**
- **Azure**
- **Google Cloud**
- **Kubernetes**
- **M365**
- **Github**

Prowler supports **auditing, incident response, continuous monitoring, hardening, forensic readiness, and remediation**.

### Prowler Components

- **Prowler CLI** (Command Line Interface) – Known as **Prowler Open Source**.
- **Prowler Cloud** – A managed service built on top of Prowler CLI.
  More information: [Prowler Cloud](https://prowler.com)

## Prowler App

![Prowler App](img/overview.png)

Prowler App is a web application that simplifies running Prowler. It provides:

- A **user-friendly interface** for configuring and executing scans.
- A dashboard to **view results** and manage **security findings**.

### Installation Guide
Refer to the [Quick Start](#prowler-app-installation) section for installation steps.

## Prowler CLI

```console
prowler <provider>
```
![Prowler CLI Execution](img/short-display.png)

## Prowler Dashboard

```console
prowler dashboard
```
![Prowler Dashboard](img/dashboard.png)

Prowler includes hundreds of security controls aligned with widely recognized industry frameworks and standards, including:

- CIS Benchmarks (AWS, Azure, Microsoft 365, Kubernetes, GitHub)
- NIST SP 800-53 (rev. 4 and 5) and NIST SP 800-171
- NIST Cybersecurity Framework (CSF)
- CISA Guidelines
- FedRAMP Low & Moderate
- PCI DSS v3.2.1 and v4.0
- ISO/IEC 27001:2013 and 2022
- SOC 2
- GDPR (General Data Protection Regulation)
- HIPAA (Health Insurance Portability and Accountability Act)
- FFIEC (Federal Financial Institutions Examination Council)
- ENS RD2022 (Spanish National Security Framework)
- GxP 21 CFR Part 11 and EU Annex 11
- RBI Cybersecurity Framework (Reserve Bank of India)
- KISA ISMS-P (Korean Information Security Management System)
- MITRE ATT&CK
- AWS Well-Architected Framework (Security & Reliability Pillars)
- AWS Foundational Technical Review (FTR)
- Microsoft NIS2 Directive (EU)
- Custom threat scoring frameworks (prowler_threatscore)
- Custom security frameworks for enterprise needs

## Quick Start

### Prowler App Installation

Prowler App supports multiple installation methods based on your environment.

Refer to the [Prowler App Tutorial](tutorials/prowler-app.md) for detailed usage instructions.

=== "Docker Compose"

    _Requirements_:

    * `Docker Compose` installed: https://docs.docker.com/compose/install/.

    _Commands_:

    ``` bash
    curl -LO https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/docker-compose.yml
    curl -LO https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/.env
    docker compose up -d
    ```

    > Containers are built for `linux/amd64`. If your workstation's architecture is different, please set `DOCKER_DEFAULT_PLATFORM=linux/amd64` in your environment or use the `--platform linux/amd64` flag in the docker command.

    > Enjoy Prowler App at http://localhost:3000 by signing up with your email and password.

    ???+ note
        You can change the environment variables in the `.env` file. Note that it is not recommended to use the default values in production environments.

    ???+ note
        There is a development mode available, you can use the file https://github.com/prowler-cloud/prowler/blob/master/docker-compose-dev.yml to run the app in development mode.

    ???+ warning
        Google and GitHub authentication is only available in [Prowler Cloud](https://prowler.com).

=== "GitHub"

    _Requirements_:

    * `git` installed.
    * `poetry` installed: [poetry installation](https://python-poetry.org/docs/#installation).
    * `npm` installed: [npm installation](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).
    * `Docker Compose` installed: https://docs.docker.com/compose/install/.

    ???+ warning
        Make sure to have `api/.env` and `ui/.env.local` files with the required environment variables. You can find the required environment variables in the [`api/.env.template`](https://github.com/prowler-cloud/prowler/blob/master/api/.env.example) and [`ui/.env.template`](https://github.com/prowler-cloud/prowler/blob/master/ui/.env.template) files.

    _Commands to run the API_:

    ``` bash
    git clone https://github.com/prowler-cloud/prowler \
    cd prowler/api \
    poetry install \
    eval $(poetry env activate) \
    set -a \
    source .env \
    docker compose up postgres valkey -d \
    cd src/backend \
    python manage.py migrate --database admin \
    gunicorn -c config/guniconf.py config.wsgi:application
    ```

    ???+ important
        Starting from Poetry v2.0.0, `poetry shell` has been deprecated in favor of `poetry env activate`.

        If your poetry version is below 2.0.0 you must keep using `poetry shell` to activate your environment.
        In case you have any doubts, consult the Poetry environment activation guide: https://python-poetry.org/docs/managing-environments/#activating-the-environment

    > Now, you can access the API documentation at http://localhost:8080/api/v1/docs.

    _Commands to run the API Worker_:

    ``` bash
    git clone https://github.com/prowler-cloud/prowler \
    cd prowler/api \
    poetry install \
    eval $(poetry env activate) \
    set -a \
    source .env \
    cd src/backend \
    python -m celery -A config.celery worker -l info -E
    ```

    _Commands to run the API Scheduler_:

    ``` bash
    git clone https://github.com/prowler-cloud/prowler \
    cd prowler/api \
    poetry install \
    eval $(poetry env activate) \
    set -a \
    source .env \
    cd src/backend \
    python -m celery -A config.celery beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
    ```

    _Commands to run the UI_:

    ``` bash
    git clone https://github.com/prowler-cloud/prowler \
    cd prowler/ui \
    npm install \
    npm run build \
    npm start
    ```

    > Enjoy Prowler App at http://localhost:3000 by signing up with your email and password.

    ???+ warning
        Google and GitHub authentication is only available in [Prowler Cloud](https://prowler.com).

### Prowler CLI Installation

Prowler is available as a project in [PyPI](https://pypi.org/project/prowler/). Consequently, it can be installed as Python package with `Python >= 3.9, <= 3.12`:

=== "pipx"

    [pipx](https://pipx.pypa.io/stable/) is a tool to install Python applications in isolated environments. It is recommended to use `pipx` for a global installation.

    _Requirements_:

    * `Python >= 3.9, <= 3.12`
    * `pipx` installed: [pipx installation](https://pipx.pypa.io/stable/installation/).
    * AWS, GCP, Azure and/or Kubernetes credentials

    _Commands_:

    ``` bash
    pipx install prowler
    prowler -v
    ```

    To upgrade Prowler to the latest version, run:

    ``` bash
    pipx upgrade prowler
    ```

=== "pip"

    ???+ warning
        This method is not recommended because it will modify the environment which you choose to install. Consider using [pipx](https://docs.prowler.com/projects/prowler-open-source/en/latest/#__tabbed_1_1) for a global installation.

    _Requirements_:

    * `Python >= 3.9, <= 3.12`
    * `Python pip >= 21.0.0`
    * AWS, GCP, Azure, M365 and/or Kubernetes credentials

    _Commands_:

    ``` bash
    pip install prowler
    prowler -v
    ```

    To upgrade Prowler to the latest version, run:

    ``` bash
    pip install --upgrade prowler
    ```

=== "Docker"

    _Requirements_:

    * Have `docker` installed: https://docs.docker.com/get-docker/.
    * In the command below, change `-v` to your local directory path in order to access the reports.
    * AWS, GCP, Azure and/or Kubernetes credentials

    > Containers are built for `linux/amd64`. If your workstation's architecture is different, please set `DOCKER_DEFAULT_PLATFORM=linux/amd64` in your environment or use the `--platform linux/amd64` flag in the docker command.

    _Commands_:

    ``` bash
    docker run -ti --rm -v /your/local/dir/prowler-output:/home/prowler/output \
    --name prowler \
    --env AWS_ACCESS_KEY_ID \
    --env AWS_SECRET_ACCESS_KEY \
    --env AWS_SESSION_TOKEN toniblyx/prowler:latest
    ```

=== "GitHub"

    _Requirements for Developers_:

    * `git`
    * `poetry` installed: [poetry installation](https://python-poetry.org/docs/#installation).
    * AWS, GCP, Azure and/or Kubernetes credentials

    _Commands_:

    ```
    git clone https://github.com/prowler-cloud/prowler
    cd prowler
    poetry install
    poetry run python prowler-cli.py -v
    ```
    ???+ note
        If you want to clone Prowler from Windows, use `git config core.longpaths true` to allow long file paths.

=== "Amazon Linux 2"

    _Requirements_:

    * `Python >= 3.9, <= 3.12`
    * AWS, GCP, Azure and/or Kubernetes credentials

    _Commands_:

    ```
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    pipx install prowler
    prowler -v
    ```

=== "Ubuntu"

    _Requirements_:

    * `Ubuntu 23.04` or above, if you are using an older version of Ubuntu check [pipx installation](https://docs.prowler.com/projects/prowler-open-source/en/latest/#__tabbed_1_1) and ensure you have `Python >= 3.9, <= 3.12`.
    * `Python >= 3.9, <= 3.12`
    * AWS, GCP, Azure and/or Kubernetes credentials

    _Commands_:

    ``` bash
    sudo apt update
    sudo apt install pipx
    pipx ensurepath
    pipx install prowler
    prowler -v
    ```

=== "Brew"

    _Requirements_:

    * `Brew` installed in your Mac or Linux
    * AWS, GCP, Azure and/or Kubernetes credentials

    _Commands_:

    ``` bash
    brew install prowler
    prowler -v
    ```

=== "AWS CloudShell"

    After the migration of AWS CloudShell from Amazon Linux 2 to Amazon Linux 2023 [[1]](https://aws.amazon.com/about-aws/whats-new/2023/12/aws-cloudshell-migrated-al2023/) [[2]](https://docs.aws.amazon.com/cloudshell/latest/userguide/cloudshell-AL2023-migration.html), there is no longer a need to manually compile Python 3.9 as it is already included in AL2023. Prowler can thus be easily installed following the generic method of installation via pip. Follow the steps below to successfully execute Prowler v4 in AWS CloudShell:

    _Requirements_:

    * Open AWS CloudShell `bash`.

    _Commands_:

    ```bash
    sudo bash
    adduser prowler
    su prowler
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    pipx install prowler
    cd /tmp
    prowler aws
    ```

    ???+ note
        To download the results from AWS CloudShell, select Actions -> Download File and add the full path of each file. For the CSV file it will be something like `/tmp/output/prowler-output-123456789012-20221220191331.csv`

=== "Azure CloudShell"

    _Requirements_:

    * Open Azure CloudShell `bash`.

    _Commands_:

    ```bash
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    pipx install prowler
    cd /tmp
    prowler azure --az-cli-auth
    ```
## Prowler container versions

The available versions of Prowler CLI are the following:

- `latest`: in sync with `master` branch (please note that it is not a stable version)
- `v4-latest`: in sync with `v4` branch (please note that it is not a stable version)
- `v3-latest`: in sync with `v3` branch (please note that it is not a stable version)
- `<x.y.z>` (release): you can find the releases [here](https://github.com/prowler-cloud/prowler/releases), those are stable releases.
- `stable`: this tag always point to the latest release.
- `v4-stable`: this tag always point to the latest release for v4.
- `v3-stable`: this tag always point to the latest release for v3.

The container images are available here:

- Prowler CLI:

    - [DockerHub](https://hub.docker.com/r/toniblyx/prowler/tags)
    - [AWS Public ECR](https://gallery.ecr.aws/prowler-cloud/prowler)

- Prowler App:

    - [DockerHub - Prowler UI](https://hub.docker.com/r/prowlercloud/prowler-ui/tags)
    - [DockerHub - Prowler API](https://hub.docker.com/r/prowlercloud/prowler-api/tags)

## High level architecture

You can run Prowler from your workstation, a Kubernetes Job, a Google Compute Engine, an Azure VM, an EC2 instance, Fargate or any other container, CloudShell and many more.

![Architecture](img/architecture.png)

### Prowler App

The **Prowler App** consists of three main components:

- **Prowler UI**: A user-friendly web interface for running Prowler and viewing results, powered by Next.js.
- **Prowler API**: The backend API that executes Prowler scans and stores the results, built with Django REST Framework.
- **Prowler SDK**: A Python SDK that integrates with Prowler CLI for advanced functionality.

The app leverages the following supporting infrastructure:

- **PostgreSQL**: Used for persistent storage of scan results.
- **Celery Workers**: Facilitate asynchronous execution of Prowler scans.
- **Valkey**: An in-memory database serving as a message broker for the Celery workers.

![Prowler App Architecture](img/prowler-app-architecture.png)

## Deprecations from v3

The following are the deprecations carried out from v3.

### General

- `Allowlist` now is called `Mutelist`.
- The `--quiet` option has been deprecated. From now on use the `--status` flag to select the finding's status you want to get: PASS, FAIL or MANUAL.
- All `INFO` finding's status has changed to `MANUAL`.
- The CSV output format is common for all providers.

Some output formats are now deprecated:

- The native JSON is replaced for the JSON [OCSF](https://schema.ocsf.io/) v1.1.0, common for all the providers.

### AWS
- Deprecate the AWS flag `--sts-endpoint-region` since AWS STS regional tokens are used.
- To send only FAILS to AWS Security Hub, now you must use either `--send-sh-only-fails` or `--security-hub --status FAIL`.

## Basic Usage

### Prowler App

#### **Access the App**

Go to [http://localhost:3000](http://localhost:3000) after installing the app (see [Quick Start](#prowler-app-installation)). Sign up with your email and password.

<img src="img/sign-up-button.png" alt="Sign Up Button" width="320"/>
<img src="img/sign-up.png" alt="Sign Up" width="285"/>

???+ note "User creation and default tenant behavior"

    When creating a new user, the behavior depends on whether an invitation is provided:

    - **Without an invitation**:

        - A new tenant is automatically created.
        - The new user is assigned to this tenant.
        - A set of **RBAC admin permissions** is generated and assigned to the user for the newly-created tenant.

    - **With an invitation**: The user is added to the specified tenant with the permissions defined in the invitation.

    This mechanism ensures that the first user in a newly created tenant has administrative permissions within that tenant.

#### Log In

Log in using your **email and password** to access the Prowler App.

<img src="img/log-in.png" alt="Log In" width="285"/>

#### Add a Cloud Provider

To configure a cloud provider for scanning:

1. Navigate to `Settings > Cloud Providers` and click `Add Account`.
2. Select the cloud provider you wish to scan (**AWS, GCP, Azure, Kubernetes**).
3. Enter the provider's identifier (Optional: Add an alias):
    - **AWS**: Account ID
    - **GCP**: Project ID
    - **Azure**: Subscription ID
    - **Kubernetes**: Cluster ID
    - **M36**: Domain ID
4. Follow the guided instructions to add and authenticate your credentials.

#### Start a Scan

Once credentials are successfully added and validated, Prowler initiates a scan of your cloud environment.

Click `Go to Scans` to monitor progress.

#### View Results

While the scan is running, you can review findings in the following sections:

- **Overview** – Provides a high-level summary of your scans.
  <img src="img/overview.png" alt="Overview" width="700"/>

- **Compliance** – Displays compliance insights based on security frameworks.
  <img src="img/compliance.png" alt="Compliance" width="700"/>

> For detailed usage instructions, refer to the [Prowler App Guide](tutorials/prowler-app.md).

???+ note
    Prowler will automatically scan all configured providers every **24 hours**, ensuring your cloud environment stays continuously monitored.

### Prowler CLI

#### Running Prowler

To run Prowler, you will need to specify the provider (e.g `aws`, `gcp`, `azure`, `m365`, `github` or `kubernetes`):

???+ note
    If no provider is specified, AWS is used by default for backward compatibility with Prowler v2.

```console
prowler <provider>
```
![Prowler Execution](img/short-display.png)

???+ note
    Running the `prowler` command without options will uses environment variable credentials. Refer to the [Requirements](./getting-started/requirements.md) section for credential configuration details.

#### Verbose Output

If you prefer the former verbose output, use: `--verbose`. This allows seeing more info while Prowler is running, minimal output is displayed unless verbosity is enabled.

#### Report Generation

By default, Prowler generates CSV, JSON-OCSF, and HTML reports. To generate a JSON-ASFF report (used by AWS Security Hub), specify `-M` or `--output-modes`:

```console
prowler <provider> -M csv json-asff json-ocsf html
```
The HTML report is saved in the output directory, alongside other reports. It will look like this:

![Prowler Execution](img/html-output.png)

#### Listing Available Checks and Services

To view all available checks or services within a provider:, use `-l`/`--list-checks` or `--list-services`.

```console
prowler <provider> --list-checks
prowler <provider> --list-services
```
#### Running Specific Checks or Services

Execute specific checks or services using `-c`/`checks` or `-s`/`services`:

```console
prowler azure --checks storage_blob_public_access_level_is_disabled
prowler aws --services s3 ec2
prowler gcp --services iam compute
prowler kubernetes --services etcd apiserver
```
#### Excluding Checks and Services

Checks and services can be excluded with `-e`/`--excluded-checks` or `--excluded-services`:

```console
prowler aws --excluded-checks s3_bucket_public_access
prowler azure --excluded-services defender iam
prowler gcp --excluded-services kms
prowler kubernetes --excluded-services controllermanager
```
#### Additional Options

Explore more advanced time-saving execution methods in the [Miscellaneous](tutorials/misc.md) section.

To access the help menu and view all available options, use: `-h`/`--help`:

```console
prowler --help
```

#### AWS

Use a custom AWS profile with `-p`/`--profile` and/or the AWS regions you want to audit with `-f`/`--filter-region`:

```console
prowler aws --profile custom-profile -f us-east-1 eu-south-2
```

???+ note
    By default, `prowler` will scan all AWS regions.

See more details about AWS Authentication in the [Requirements](getting-started/requirements.md#aws) section.

#### Azure

Azure requires specifying the auth method:

```console
# To use service principal authentication
prowler azure --sp-env-auth

# To use az cli authentication
prowler azure --az-cli-auth

# To use browser authentication
prowler azure --browser-auth --tenant-id "XXXXXXXX"

# To use managed identity auth
prowler azure --managed-identity-auth
```

See more details about Azure Authentication in [Requirements](getting-started/requirements.md#azure)

By default, Prowler scans all the subscriptions for which it has permissions. To scan a single or various specific subscription you can use the following flag (using az cli auth as example):

```console
prowler azure --az-cli-auth --subscription-ids <subscription ID 1> <subscription ID 2> ... <subscription ID N>
```
#### Google Cloud

- **User Account Credentials**

    By default, Prowler uses **User Account credentials**. You can configure your account using:

    - `gcloud init` – Set up a new account.
    - `gcloud config set account <account>` – Switch to an existing account.

    Once configured, obtain access credentials using: `gcloud auth application-default login`.

- **Service Account Authentication**

    Alternatively, you can use Service Account credentials:

    Generate and download Service Account keys in JSON format. Refer to [Google IAM documentation](https://cloud.google.com/iam/docs/creating-managing-service-account-keys) for details.

    Provide the key file location using this argument:

    ```console
    prowler gcp --credentials-file path
    ```

- **Scanning Specific GCP Projects**

    By default, Prowler scans all accessible GCP projects. To scan specific projects, use the `--project-ids` flag:

    ```console
    prowler gcp --project-ids <Project ID 1> <Project ID 2> ... <Project ID N>
    ```

#### Kubernetes

Prowler enables security scanning of Kubernetes clusters, supporting both **in-cluster** and **external** execution.

- **Non In-Cluster Execution**

    ```console
    prowler kubernetes --kubeconfig-file path
    ```
    ???+ note
        If no `--kubeconfig-file` is provided, Prowler will use the default KubeConfig file location (`~/.kube/config`).

- **In-Cluster Execution**

    To run Prowler inside the cluster, apply the provided YAML configuration to deploy a job in a new namespace:

    ```console
    kubectl apply -f kubernetes/prowler-sa.yaml
    kubectl apply -f kubernetes/job.yaml
    kubectl apply -f kubernetes/prowler-role.yaml
    kubectl apply -f kubernetes/prowler-rolebinding.yaml
    kubectl get pods --namespace prowler-ns --> prowler-XXXXX
    kubectl logs prowler-XXXXX --namespace prowler-ns
    ```

    ???+ note
        By default, Prowler scans all namespaces in the active Kubernetes context. Use the `--context`flag to specify the context to be scanned and `--namespaces` to restrict scanning to specific namespaces.

#### Microsoft 365

Microsoft 365 requires specifying the auth method:

```console

# To use service principal authentication for MSGraph and PowerShell modules
prowler m365 --sp-env-auth

# To use both service principal (for MSGraph) and user credentials (for PowerShell modules)
prowler m365 --env-auth

# To use az cli authentication
prowler m365 --az-cli-auth

# To use browser authentication
prowler m365 --browser-auth --tenant-id "XXXXXXXX"

```

See more details about M365 Authentication in the [Requirements](getting-started/requirements.md#microsoft-365) section.

#### GitHub

Prowler enables security scanning of your **GitHub account**, including **Repositories**, **Organizations** and **Applications**.

- **Supported Authentication Methods**

    Authenticate using one of the following methods:

    ```console
    # Personal Access Token (PAT):
    prowler github --personal-access-token pat

    # OAuth App Token:
    prowler github --oauth-app-token oauth_token

    # GitHub App Credentials:
    prowler github --github-app-id app_id --github-app-key app_key
    ```

    ???+ note
        If no login method is explicitly provided, Prowler will automatically attempt to authenticate using environment variables in the following order of precedence:

        1. `GITHUB_PERSONAL_ACCESS_TOKEN`
        2. `OAUTH_APP_TOKEN`
        3. `GITHUB_APP_ID` and `GITHUB_APP_KEY`

#### Infrastructure as Code (IaC)

Prowler's Infrastructure as Code (IaC) provider enables you to scan local infrastructure code for security and compliance issues using [Checkov](https://www.checkov.io/). This provider supports a wide range of IaC frameworks, allowing you to assess your code before deployment.

```console
# Scan a directory for IaC files
prowler iac --scan-path ./my-iac-directory

# Specify frameworks to scan (default: all)
prowler iac --scan-path ./my-iac-directory --frameworks terraform kubernetes

# Exclude specific paths
prowler iac --scan-path ./my-iac-directory --exclude-path ./my-iac-directory/test,./my-iac-directory/examples
```

???+ note
    - The IaC provider does not require cloud authentication
    - It is ideal for CI/CD pipelines and local development environments
    - For more details on supported frameworks and rules, see the [Checkov documentation](https://www.checkov.io/1.Welcome/Quick%20Start.html)

See more details about IaC scanning in the [IaC Tutorial](tutorials/iac/getting-started-iac.md) section.

## Prowler v2 Documentation

For **Prowler v2 Documentation**, refer to the [official repository](https://github.com/prowler-cloud/prowler/blob/8818f47333a0c1c1a457453c87af0ea5b89a385f/README.md).
