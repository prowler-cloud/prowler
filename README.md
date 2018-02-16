# Prowler: AWS CIS Benchmark Tool

## Table of Contents  
- [Description](#description)
- [Features](#features)  
- [Requirements](#requirements)  
- [Usage](#usage)
- [Fix](#fix)
- [Screenshots](#screenshots)
- [Troubleshooting](#troubleshooting)
- [Extras](#extras)
- [Forensics Ready Checks](#forensics-ready-checks)
- [Add Custom Checks](#add-custom-checks)
- [Third Party Integrations](#third-party-integrations)

## Description

Tool based on AWS-CLI commands for AWS account security assessment and hardening, following guidelines of the [CIS Amazon Web Services Foundations Benchmark 1.1 ](https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf)

## Features

It covers hardening and security best practices for all AWS regions related to:

- Identity and Access Management (24 checks)
- Logging (8 checks)
- Monitoring (15 checks)
- Networking (5 checks)
- Extras (22 checks) *see Extras section*
- Forensics related group of checks

For a comprehesive list and resolution look at the guide on the link above.

With Prowler you can:
- get a colourish or monochrome report
- a CSV format report for diff
- run specific checks without having to run the entire report
- check multiple AWS accounts in parallel

## Requirements
This script has been written in bash using AWS-CLI and it works in Linux and OSX.

- Make sure your AWS-CLI is installed on your workstation, with Python pip already installed:
```
pip install awscli
```
Or install it using "brew", "apt", "yum" or manually from https://aws.amazon.com/cli/

- Previous steps, from your workstation:
```
git clone https://github.com/Alfresco/prowler
cd prowler
```

- Make sure you have properly configured your AWS-CLI with a valid Access Key and Region:
```
aws configure
```

- Make sure your Secret and Access Keys are associated to a user with proper permissions to do all checks. To make sure add SecurityAuditor default policy to your user. Policy ARN is

```
arn:aws:iam::aws:policy/SecurityAudit
```
> In some cases you may need more list or get permissions in some services, look at the Troubleshooting section for a more comprehensive policy if you find issues with the default SecurityAudit policy.

## Usage

1 - Run the prowler.sh command without options (it will use your environment variable credentials if exist or default in ~/.aws/credentials file and run checks over all regions when needed, default region is us-east-1):

```
./prowler
```

2 - For custom AWS-CLI profile and region, use the following: (it will use your custom profile and run checks over all regions when needed):

```
./prowler -p custom-profile -r us-east-1
```

3 - For a single check use option -c:

```
./prowler -c check310
```
or for custom profile and region
```
./prowler -p custom-profile -r us-east-1 -c check11
```
or for a group of checks use group name:
```
./prowler -c check3
```

Valid check numbers are based on the AWS CIS Benchmark guide, so 1.1 is check11 and 3.10 is check310

4 - If you want to save your report for later analysis:
```
./prowler > prowler-report.txt
```
or if you want a colored HTML report do:
```
pip install ansi2html
./prowler | ansi2html -la > report.html
```
or if you want a pipe-delimited report file, do:
```
./prowler -M csv > output.psv
```

5 - To perform an assessment based on CIS Profile Definitions you can use level1 or level2 with `-c` flag, more information about this [here, page 8](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf):
```
./prowler -c level1
```

6 - If you want to run Prowler to check multiple AWS accounts in parallel (runs up to 4 simultaneously `-P 4`):

```
grep -E '^\[([0-9A-Aa-z_-]+)\]'  ~/.aws/credentials | tr -d '][' | shuf |  \
xargs -n 1 -L 1 -I @ -r -P 4 ./prowler -p @ -M csv  2> /dev/null  >> all-accounts.csv
```

7 - For help use:

```
./prowler -h

USAGE:
      prowler -p <profile> -r <region> [ -h ]
  Options:
      -p <profile>        specify your AWS profile to use (i.e.: default)
      -r <region>         specify an AWS region to direct API requests to
                            (i.e.: us-east-1), all regions are checked anyway
      -c <check_id>       specify a check number or group from the AWS CIS benchmark
                            (i.e.: "check11" for check 1.1, "check3" for entire section 3, "level1" for CIS Level 1 Profile Definitions or "forensics-ready")
      -f <filterregion>   specify an AWS region to run checks against
                            (i.e.: us-west-1)
      -m <maxitems>       specify the maximum number of items to return for long-running requests (default: 100)
      -M <mode>           output mode: text (defalut), mono, csv (separator is ","; data is on stdout; progress on stderr)
      -k                  keep the credential report
      -n                  show check numbers to sort easier
                            (i.e.: 1.01 instead of 1.1)
      -l                  list all available checks only (does not perform any check)
      -e                  exclude extras
      -h                  this help

```
## Fix:
 Check your report and fix the issues following all specific guidelines per check in https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf

## Screenshots

- Sample screenshot of report first lines:
 <img width="1125" alt="screenshot 2016-09-13 16 05 42" src="https://cloud.githubusercontent.com/assets/3985464/18489640/50fe6824-79cc-11e6-8a9c-e788b88a8a6b.png">

- Sample screnshot of single check for check 3.3:
<img width="1006" alt="screenshot 2016-09-14 13 20 46" src="https://cloud.githubusercontent.com/assets/3985464/18522590/a04ca9a6-7a7e-11e6-8730-b545c9204990.png">

## Troubleshooting

### STS expired token
If you are using an STS token for AWS-CLI and your session is expired you probably get this error:

```
A client error (ExpiredToken) occurred when calling the GenerateCredentialReport operation: The security token included in the request is expired
```
To fix it, please renew your token by authenticating again to the AWS API.

### Custom IAM Policy
Instead of using default policy SecurityAudit for the account you use for checks you may need to create a custom policy with a few more permissions (get and list, not change!) here you go a good example for a "ProwlerPolicyReadOnly":

```
{
    "Version": "2012-10-17",
    "Statement": [{
        "Action": [
            "acm:describecertificate",
            "acm:listcertificates",
            "autoscaling:describe*",
            "cloudformation:describestack*",
            "cloudformation:getstackpolicy",
            "cloudformation:gettemplate",
            "cloudformation:liststack*",
            "cloudfront:get*",
            "cloudfront:list*",
            "cloudtrail:describetrails",
            "cloudtrail:gettrailstatus",
            "cloudtrail:listtags",
            "cloudwatch:describe*",
            "cloudwatchlogs:describeloggroups",
            "cloudwatchlogs:describemetricfilters",
            "codecommit:batchgetrepositories",
            "codecommit:getbranch",
            "codecommit:getobjectidentifier",
            "codecommit:getrepository",
            "codecommit:list*",
            "codedeploy:batch*",
            "codedeploy:get*",
            "codedeploy:list*",
            "config:deliver*",
            "config:describe*",
            "config:get*",
            "datapipeline:describeobjects",
            "datapipeline:describepipelines",
            "datapipeline:evaluateexpression",
            "datapipeline:getpipelinedefinition",
            "datapipeline:listpipelines",
            "datapipeline:queryobjects",
            "datapipeline:validatepipelinedefinition",
            "directconnect:describe*",
            "dynamodb:listtables",
            "ec2:describe*",
            "ecs:describe*",
            "ecs:list*",
            "elasticache:describe*",
            "elasticbeanstalk:describe*",
            "elasticloadbalancing:describe*",
            "elasticmapreduce:describejobflows",
            "elasticmapreduce:listclusters",
            "es:describeelasticsearchdomainconfig",
            "es:listdomainnames",
            "firehose:describe*",
            "firehose:list*",
            "glacier:listvaults",
            "iam:generatecredentialreport",
            "iam:get*",
            "iam:list*",
            "kms:describe*",
            "kms:get*",
            "kms:list*",
            "lambda:getpolicy",
            "lambda:listfunctions",
            "logs:DescribeMetricFilters",
            "rds:describe*",
            "rds:downloaddblogfileportion",
            "rds:listtagsforresource",
            "redshift:describe*",
            "route53:getchange",
            "route53:getcheckeripranges",
            "route53:getgeolocation",
            "route53:gethealthcheck",
            "route53:gethealthcheckcount",
            "route53:gethealthchecklastfailurereason",
            "route53:gethostedzone",
            "route53:gethostedzonecount",
            "route53:getreusabledelegationset",
            "route53:listgeolocations",
            "route53:listhealthchecks",
            "route53:listhostedzones",
            "route53:listhostedzonesbyname",
            "route53:listresourcerecordsets",
            "route53:listreusabledelegationsets",
            "route53:listtagsforresource",
            "route53:listtagsforresources",
            "route53domains:getdomaindetail",
            "route53domains:getoperationdetail",
            "route53domains:listdomains",
            "route53domains:listoperations",
            "route53domains:listtagsfordomain",
            "s3:getbucket*",
            "s3:getlifecycleconfiguration",
            "s3:getobjectacl",
            "s3:getobjectversionacl",
            "s3:listallmybuckets",
            "sdb:domainmetadata",
            "sdb:listdomains",
            "ses:getidentitydkimattributes",
            "ses:getidentityverificationattributes",
            "ses:listidentities",
            "ses:listverifiedemailaddresses",
            "ses:sendemail",
            "sns:gettopicattributes",
            "sns:listsubscriptionsbytopic",
            "sns:listtopics",
            "sqs:getqueueattributes",
            "sqs:listqueues",
            "tag:getresources",
            "tag:gettagkeys"
        ],
        "Effect": "Allow",
        "Resource": "*"
    }]
}
```

### Incremental IAM Policy

Alternatively, here is a policy which defines the permissions which are NOT present in the AWS Managed SecurityAudit policy. Attach both this policy and the AWS Managed SecurityAudit policy to the group and you're good to go.  

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "acm:DescribeCertificate",
        "acm:ListCertificates",
        "cloudwatchlogs:describeLogGroups",
        "cloudwatchlogs:DescribeMetricFilters",
        "es:DescribeElasticsearchDomainConfig",
        "ses:GetIdentityVerificationAttributes",
        "sns:ListSubscriptionsByTopic"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
```

### Bootstrap Script

Quick bash script to set up a "prowler" IAM user and "SecurityAudit" group with the required permissions. To run the script below, you need user with administrative permissions; set the AWS_DEFAULT_PROFILE to use that account.

```
export AWS_DEFAULT_PROFILE=default
export ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' | tr -d '"')
aws iam create-group --group-name SecurityAudit
aws iam create-policy --policy-name ProwlerAuditAdditions --policy-document file://$(pwd)/prowler-policy-additions.json
aws iam attach-group-policy --group-name SecurityAudit --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-group-policy --group-name SecurityAudit --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/ProwlerAuditAdditions
aws iam create-user --user-name prowler
aws iam add-user-to-group --user-name prowler --group-name SecurityAudit
aws iam create-access-key --user-name prowler
unset ACCOUNT_ID AWS_DEFAULT_PROFILE
```

The `aws iam create-access-key` command will output the secret access key and the key id; keep these somewhere safe, and add them to ~/.aws/credentials with an appropriate profile name to use them with prowler. This is the only time they secret key will be shown.  If you loose it, you will need to generate a replacement.

## Extras
We are adding additional checks to improve the information gather from each account, these checks are out of the scope of the CIS benchmark for AWS but we consider them very helpful to get to know each AWS account set up and find issues on it.

Note: Some of these checks for publicly facing resources may not actually be fully public due to other layered controls like S3 Bucket Policies, Security Groups or Network ACLs.

At this moment we have 22 extra checks:

- 7.1 (`extra71`) Ensure users with AdministratorAccess policy have MFA tokens enabled (Not Scored) (Not part of CIS benchmark)
- 7.2 (`extra72`) Ensure there are no EBS Snapshots set as Public (Not Scored) (Not part of CIS benchmark)
- 7.3 (`extra73`) Ensure there are no S3 buckets open to the Everyone or Any AWS user (Not Scored) (Not part of CIS benchmark)
- 7.4 (`extra74`) Ensure there are no Security Groups without ingress filtering being used (Not Scored) (Not part of CIS benchmark)
- 7.5 (`extra75`) Ensure there are no Security Groups not being used (Not Scored) (Not part of CIS benchmark)
- 7.6 (`extra76`) Ensure there are no EC2 AMIs set as Public (Not Scored) (Not part of CIS benchmark)
- 7.7 (`extra77`) Ensure there are no ECR repositories set as Public (Not Scored) (Not part of CIS benchmark)
- 7.8 (`extra78`) Ensure there are no Public Accessible RDS instances (Not Scored) (Not part of CIS benchmark)
- 7.9 (`extra79`) Check for internet facing Elastic Load Balancers (Not Scored) (Not part of CIS benchmark)
- 7.10 (`extra710`) Check for internet facing EC2 Instances (Not Scored) (Not part of CIS benchmark)
- 7.11 (`extra711`) Check for Publicly Accessible Redshift Clusters (Not Scored) (Not part of CIS benchmark)
- 7.12 (`extra712`) Check if Amazon Macie is enabled (Not Scored) (Not part of CIS benchmark)
- 7.13 (`extra713`) Check if GuardDuty is enabled (Not Scored) (Not part of CIS benchmark)
- 7.14 (`extra714`) Check if CloudFront distributions have logging enabled (Not Scored) (Not part of CIS benchmark)
- 7.15 (`extra715`) Check if Elasticsearch Service domains have logging enabled (Not Scored) (Not part of CIS benchmark)
- 7.16 (`extra716`) Check if Elasticsearch Service domains allow open access (Not Scored) (Not part of CIS benchmark)
- 7.17 (`extra717`) Check if Elastic Load Balancers have logging enabled (Not Scored) (Not part of CIS benchmark)
- 7.18 (`extra718`) Check if S3 buckets have server access logging enabled (Not Scored) (Not part of CIS benchmark)
- 7.19 (`extra719`) Check if Route53 hosted zones are logging queries to CloudWatch Logs (Not Scored) (Not part of CIS benchmark)
- 7.20 (`extra720`) Check if Lambda functions are being recorded by CloudTrail (Not Scored) (Not part of CIS benchmark)
- 7.21 (`extra721`) Check if Redshift cluster has audit logging enabled (Not Scored) (Not part of CIS benchmark)
- 7.22 (`extra722`) Check if API Gateway has logging enabled (Not Scored) (Not part of CIS benchmark)


To check all extras in one command:
```
./prowler -c extras
```
or to run just one of the checks:
```
./prowler -c extraNUMBER
```

## Forensics Ready Checks

With this group of checks, Prowler looks if each service with logging or audit capabilities has them enabled to ensure all needed evidences are recorded and collected for an eventual digital forensic investigation in case of incident. List of checks part of this group:
- 2.1  Ensure CloudTrail is enabled in all regions (Scored)
- 2.2  Ensure CloudTrail log file validation is enabled (Scored)
- 2.3  Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)
- 2.4  Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)
- 2.5  Ensure AWS Config is enabled in all regions (Scored)
- 2.6  Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)
- 2.7  Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)
- 4.3  Ensure VPC Flow Logging is Enabled in all VPCs (Scored)
- 7.12  Check if Amazon Macie is enabled (Not Scored) (Not part of CIS benchmark)
- 7.13  Check if GuardDuty is enabled (Not Scored) (Not part of CIS benchmark)
- 7.14  Check if CloudFront distributions have logging enabled (Not Scored) (Not part of CIS benchmark)
- 7.15  Check if Elasticsearch Service domains have logging enabled (Not Scored) (Not part of CIS benchmark)
- 7.17  Check if Elastic Load Balancers have logging enabled (Not Scored) (Not part of CIS benchmark)
- 7.18  Check if S3 buckets have server access logging enabled (Not Scored) (Not part of CIS benchmark)
- 7.19  Check if Route53 hosted zones are logging queries to CloudWatch Logs (Not Scored) (Not part of CIS benchmark)
- 7.20  Check if Lambda functions are being recorded by CloudTrail (Not Scored) (Not part of CIS benchmark)
- 7.21  Check if Redshift cluster has audit logging enabled (Not Scored) (Not part of CIS benchmark)
- 7.22  Check if API Gateway has logging enabled (Not Scored) (Not part of CIS benchmark)

The `forensics-ready` group of checks uses existing and extra checks. To get a forensics readiness report, run this command:
```
./prowler -c forensics-ready
```

## Add Custom Checks

In order to add any new check feel free to create a new extra check in the extras section. To do so, you will need to follow these steps:

1. use any existing extra check as reference
2. add `ID7N` and `TITLE7N`, where N is a new check number part of the extras section (7) around line 361 `# List of checks IDs and Titles`
3. add your new extra check function name at `callCheck` function (around line 1817) and below in that case inside extras option (around line 1853)
4. finally add it in `# List only check tittles` around line 1930
5. save changes and run it as ./prowler -c extraNN
6. send me a pull request! :)

## Third Party Integrations

### Telegram
Javier Pecete has done an awesome job integrating Prowler with Telegram, you have more details here https://github.com/i4specete/ServerTelegramBot
### Cloud Security Suite
The guys of SecurityFTW have added Prowler in their Cloud Security Suite along with other cool security tools https://github.com/SecurityFTW/cs-suite
