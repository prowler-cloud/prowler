# End to End Tests

This folder contains the end to end tests for Prowler.

End to end tests are tests that run Prowler against a simulated environment, such as LocalStack.

## Index

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Requirements](#requirements)
- [Instructions](#instructions)
  - [1. Start LocalStack](#1-start-localstack)
  - [2. Get configuration from LocalStack](#2-get-configuration-from-localstack)
  - [3. Configure environment variables](#3-configure-environment-variables)
    - [Automatic generation](#automatic-generation)
    - [Manual generation](#manual-generation)
  - [4. Run Prowler](#4-run-prowler)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Requirements

To run the tests, you need to have the following installed:

- [LocalStack](https://localstack.cloud/)
- Docker

## Instructions

### 1. Start LocalStack

You run LocalStack using their UI or their CLI. 

### 2. Get configuration from LocalStack

LocalStack provides an URL that you can use to access the API. By default, it is `http://localhost.localstack.cloud:4566`.

### 3. Configure environment variables

At this point you need to configure the environment variables for Prowler to use the LocalStack URL.

The easiest way is to create a shell script that will generate the environment variables for you.

#### Automatic generation

To generate the environment variables automatically, you can use the `generate_env_file.sh` script.

This will generate the environment variables based on the role that you want to assume and save them to a `.env` file.

> Note: The script assumes that you have the `jq` tool installed.

#### Manual generation

You can also manually generate the environment variables by running the script and following the instructions.

1 - Check the identity of the role that you want to assume.

```bash
# This value is random. The only requirement is that it is not empty.
export AWS_SECURITY_TOKEN=LSIAXXXXXXXXXXXXXXXXX

# Set the endpoint URL pointing to LocalStack
export AWS_ENDPOINT_URL=http://localhost.localstack.cloud:4566
export AWS_ENDPOINT_URL_S3=http://localhost.localstack.cloud:4566

> aws sts get-caller-identity --endpoint-url http://localhost.localstack.cloud:4566
```

2 - Generating the temporary credentials.

```bash
# This value is random. The only requirement is that it is not empty.
export AWS_SECURITY_TOKEN=LSIAXXXXXXXXXXXXXXXXX

# Set the endpoint URL pointing to LocalStack
export AWS_ENDPOINT_URL=http://localhost.localstack.cloud:4566
export AWS_ENDPOINT_URL_S3=http://localhost.localstack.cloud:4566

> aws sts assume-role --role-arn "arn:aws:iam::000000000000:role/demo" --role-session-name "sessionName"
```

3 - Extract the AccessKeyId and SecretAccessKey from the JSON.

```bash
export AWS_ACCESS_KEY_ID={AccessKeyId}
export AWS_SECRET_ACCESS_KEY={SecretAccessKey}
```

4 - Update the environment variables.

```bash
export AWS_ACCESS_KEY_ID=LSIAQAAAAAAABZPWHL2V
export AWS_SECRET_ACCESS_KEY=yQQReyzUv0y04XYjWcqhZcvthCbXqO4JDg8uI5Um
export AWS_ENDPOINT_URL=http://localhost.localstack.cloud:4566
export AWS_ENDPOINT_URL_S3=http://localhost.localstack.cloud:4566
export AWS_ROLE_ARN=arn:aws:iam::000000000000:role/demo
export PROWLER_LOCAL_DEBUG=1
```

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
! To tell Prowler to use the LocalStack URL, You have to set the environment variable `PROWLER_LOCAL_DEBUG` to `1`. !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

### 4. Run Prowler

```bash
> source .env
> python3 prowler.py -v
```

> Note: The script assumes that you have generated the `.env` file from the script above.

## Running tests

### 1. Populate the environment

In order to run the tests, you need to populate the environment with resources.

You can use the `populate.py` script to do that.

The script has the following arguments:

- `-e`: Number of EC2 instances to create
- `-s`: Number of S3 buckets to create
- `-g`: Number of security groups to create
- `-c`: Number of concurrent threads to use

Example:

```bash
> source .env
> python3 populate.py -e 10 -s 10 -g 10 -c 10
```

### 2. Run the tests

Once the environment is populated, you can run the Prowler:

```bash
> source .env
> python3 -m prowler aws --services ec2 s3
```
