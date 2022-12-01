<p href="https://github.com/prowler-cloud/prowler">
<img align="right" src="./img/prowler-logo.png" height="100">
</p>
<br>

# Prowler Documentation

Welcome to Prowler Documentation!

- You are currently in the **Getting Started** section where you can find general information and requirements to help you start with the tool.
- In the [Tutorials](tutorials/overview) section .
- In the [Support](support) section you can find step-by-step guides that help you accomplish specific tasks.
- In the [FAQ](faq) .

## About Prowler

**Prowler** is an Open Source security tool to perform AWS and Azure security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.

It contains hundreds of controls covering CIS, PCI-DSS, ISO27001, GDPR, HIPAA, FFIEC, SOC2, AWS FTR, ENS and custom security frameworks.

## Quick Start

Prowler is available as a project in [PyPI](https://pypi.org/project/moto/), thus can be installed using pip:

```bash
pip install prowler
prowler -v
```

## Basic Usage

To run prowler, you will need to specify the provider (e.g aws or azure):

```console
prowler <provider>
```
> Running the `prowler` command without options will use your environment variable credentials, see [Requirements](getting-started/requirements/) section to review the credentials settings.

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

### AWS

Use a custom AWS profile with `-p`/`--profile` and/or AWS regions which you want to audit with `-f`/`--filter-region`:

```console
prowler aws --profile custom-profile -f us-east-1 eu-south-2
```
> By default, `prowler` will scan all AWS regions.
