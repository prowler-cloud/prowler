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

- Make sure you have properly configure your AWS-CLI with a valid Access Key and Region:
```
aws configure
```

- Make sure your Secret and Access Keys are associated to a user with proper permissions to do all checks. To make sure add SecurityAuditor default policy to your user. Policy ARN is

```
arn:aws:iam::aws:policy/SecurityAudit
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

3 - For a single check use option -c:

```
./prowler.sh -c check310
```
or for custom profile and region
```
./prowler.sh -p custom-profile -r us-east-1 -c check11
```
Valid check numbers are like in the AWS CIS Benchmark guide, while 1.1 is check11 or 3.10 is check310

4 - For help use:

```
./prowler.sh -h

USAGE:
      prowler.sh -p <profile> -r <region> [ -v ] [ -h ]
  Options:
      -p <profile>  specify your AWS profile to use (i.e.: default)
      -r <region>   specify a desired AWS region to use (i.e.: us-east-1)
      -c <checknum> specify a check number from the AWS CIS benchmark (i.e.: check11 for check 1.1)
      -h            this help

```
## How to fix all warnings:
 Check your report and fix the issues following all specific guidelines per check in https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf

## Screenshot

 <img width="1125" alt="screenshot 2016-09-13 16 05 42" src="https://cloud.githubusercontent.com/assets/3985464/18489640/50fe6824-79cc-11e6-8a9c-e788b88a8a6b.png">

## Troubleshooting

 If you are using STS token for AWS-CLI and your session is expired you probably get this error:

```
 A client error (ExpiredToken) occurred when calling the GenerateCredentialReport operation: The security token included in the request is expired
 ```
 To fix it, please renew your token by authenticating again to the AWS API.
