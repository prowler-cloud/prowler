# Installing Prowler in AWS CloudShell

## Following the migration of AWS CloudShell from

AWS CloudShell has migrated from Amazon Linux 2 to Amazon Linux 2023 [[1]](https://aws.amazon.com/about-aws/whats-new/2023/12/aws-cloudshell-migrated-al2023/) [[2]](https://docs.aws.amazon.com/cloudshell/latest/userguide/cloudshell-AL2023-migration.html). With this transition, Python 3.9 is now included by default in AL2023, eliminating the need for manual compilation.

To install Prowler v4 in AWS CloudShell, follow the standard installation method using pip:

```shell
sudo bash
adduser prowler
su prowler
pip install prowler
cd /tmp
prowler aws
```

## Downloading Files from AWS CloudShell

To download results from AWS CloudShell:

- Select Actions → Download File.

- Specify the full file path of each file you wish to download. For example, downloading a CSV file would require providing its complete path, as in: `/home/cloudshell-user/output/prowler-output-123456789012-20221220191331.csv`

## Cloning Prowler from GitHub

Due to the limited storage in AWS CloudShell's home directory, installing Poetry dependencies for running Prowler from GitHub can be problematic. The following workaround ensures successful installation: The following is a workaround to solve this issue:

```shell
sudo bash
adduser prowler
su prowler
git clone https://github.com/prowler-cloud/prowler.git
cd prowler
pip install poetry
mkdir /tmp/poetry
poetry config cache-dir /tmp/poetry
eval $(poetry env activate)
poetry install
python prowler-cli.py -v
```

> [!IMPORTANT]
> Starting from Poetry v2.0.0, `poetry shell` has been deprecated in favor of `poetry env activate`.
>
> If your Poetry version is below v2.0.0, continue using `poetry shell` to activate your environment. For further guidance, refer to the Poetry Environment Activation Guide https://python-poetry.org/docs/managing-environments/#activating-the-environment.
