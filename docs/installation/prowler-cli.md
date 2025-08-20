
## Installation

Prowler is available as a project in [PyPI](https://pypi.org/project/prowler/). Install it as a Python package with `Python >= 3.9, <= 3.12`:

=== "pipx"

    [pipx](https://pipx.pypa.io/stable/) installs Python applications in isolated environments. Use `pipx` for global installation.

    _Requirements_:

    * `Python >= 3.9, <= 3.12`
    * `pipx` installed: [pipx installation](https://pipx.pypa.io/stable/installation/).
    * AWS, GCP, Azure and/or Kubernetes credentials

    _Commands_:

    ``` bash
    pipx install prowler
    prowler -v
    ```

    Upgrade Prowler to the latest version:

    ``` bash
    pipx upgrade prowler
    ```

=== "pip"

    ???+ warning
        This method modifies the chosen installation environment. Consider using [pipx](https://docs.prowler.com/projects/prowler-open-source/en/latest/#__tabbed_1_1) for global installation.

    _Requirements_:

    * `Python >= 3.9, <= 3.12`
    * `Python pip >= 21.0.0`
    * AWS, GCP, Azure, M365 and/or Kubernetes credentials

    _Commands_:

    ``` bash
    pip install prowler
    prowler -v
    ```

    Upgrade Prowler to the latest version:

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












## Container versions

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
