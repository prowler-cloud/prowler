# Prowler: AWS CIS Benchmark Tool

## Description

Tool based on AWS-CLI commands for AWS account hardening, following guidelines of the CIS Amazon Web Services Foundations Benchmark (https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf)

It covers hardening and security best practices for all regions related to:

- Identity and Access Management (15 checks)
- Logging (8 checks)
- Monitoring (16 checks)
- Neteworking (4 checks)

For a comprehesive list and resolution look at the guide on the link above.

## Requirements
This script has been written in bash using AWS-CLI and is works in Linux and OSX.

- Make sure your AWS-CLI is installed on your workstation, with Python pip already installed:
```
pip install awscli
```
Or install it using "brew", "apt", "yum" or manually from https://aws.amazon.com/cli/

- Previous steps, from your workstation:
```
git clone https://github.com/Alfresco/aws-cis-security-benchmark
cd aws-cis-security-benchmark
```

- Make sure you have properly configure your AWS-CLI with a valid Access Key and Region.
```
aws configure
```

## How to create a report

1 - Run the prowler.sh command without options:

```
./prowler.sh
```

2 - For custom AWS-CLI profile and region use:

```
./prowler.sh -p custom-profile -r us-east-1
```

3 - For help use:

```
./prowler.sh -h

USAGE:
      prowler.sh -p <profile> -r <region> [ -v ] [ -h ]
  Options:
      -p <profile>  specify your AWS profile to use (i.e.: default)
      -r <region>   specify a desired AWS region to use (i.e.: us-east-1)
      -h            this help

```

 4 - Check your report and fix the issues following all specific guidelines per check in https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf

 <img width="1123" alt="screenshot 2016-09-13 09 31 07" src="https://cloud.githubusercontent.com/assets/3985464/18475609/1b919eae-7995-11e6-93d3-5460bfd5262e.png">
