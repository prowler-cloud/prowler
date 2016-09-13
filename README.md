# Prowler / AWS CIS Benchmark Tool

## Description

Tool based on AWS-CLI commands for AWS account hardening, following guidelines of the CIS Amazon Web Services Foundations Benchmark (https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf)

It covers hardening and security best practices for:

- Identity and Access Management (15 checks)
- Logging (8 checks)
- Monitoring (16 checks)
- Neteworking (4 checks)

For a comprehesive list and resolution look at the guide on the link above.

## Requirements
This script has been written in bash using AWS-CLI and is works in Linux and OSX.

- Previous steps, from your workstation:
```
git clone https://github.com/Alfresco/aws-cis-security-benchmark
cd aws-cis-security-benchmark
```

- Make sure you have properly configure your AWS-CLI with a valid Access Key and Region.

## How to create a report

1 - Run the prowler.sh command without options:

```
./prowler.sh
```

2 - For custom AWS-CLI profile and region use

```
./prowler.sh -p profile -r
```

> NOTE: use --profile named-profile or the profile you are using for
> Okta CLI configuration, named-profile is an example value.

 2 - Perform template validation:

```
aws cloudformation validate-template \
--template-url https://s3.amazonaws.com/cf-templates-1mp42he0jarfb-us-east-1/Redding-architecture-v1.template \
--profile named-profile \
--region us-east-1
```

3 - Edit and review the input parameters Json file for the template, file Redding-architecture-parameters-v1.json. At least you have to change next parameter values:
