# AWS CloudShell

## Installation
After the migration of AWS CloudShell from Amazon Linux 2 to Amazon Linux 2023 [[1]](https://aws.amazon.com/about-aws/whats-new/2023/12/aws-cloudshell-migrated-al2023/) [[2]](https://docs.aws.amazon.com/cloudshell/latest/userguide/cloudshell-AL2023-migration.html), there is no longer a need to manually compile Python 3.9 as it's already included in AL2023. Prowler can thus be easily installed following the Generic method of installation via pip. Follow the steps below to successfully execute Prowler v3 in AWS CloudShell:
```shell
pip install prowler
prowler -v
```

## Download Files

To download the results from AWS CloudShell, select Actions -> Download File and add the full path of each file. For the CSV file it will be something like `/home/cloudshell-user/output/prowler-output-123456789012-20221220191331.csv`

## Clone Prowler from Github

The limited storage that AWS CloudShell provides for the user's home directory causes issues when installing the poetry dependencies to run Prowler from GitHub. Here is a workaround:
```shell
git clone https://github.com/prowler-cloud/prowler.git
cd prowler
git checkout master
pip install poetry
mkdir /tmp/pypoetry
poetry config cache-dir /tmp/pypoetry
poetry shell
```
