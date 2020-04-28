# Organizational Prowler Deployment <!-- omit in toc -->

Created by: Julio Delgado Jr. <delgjul@amazon.com>

Deploys Prowler to assess all Accounts in an AWS Organization.

[Prowler](https://github.com/toniblyx/prowler) is an independent third-party command line tool for AWS Security Best Practices Assessment, Auditing, Hardening, and Forensic Readiness. It evaluates guidelines of the CIS Amazon Web Services Foundations Benchmark and dozens of additional checks, including for GDPR, and HIPAA.

---

## Solution Goals

- Use minimal technologies, so solution can be more easily adopted, and further enhanced as needed.
  - [Amazon EC2](https://aws.amazon.com/ec2/), to run Prowler
  - [Amazon S3](https://aws.amazon.com/s3/), to store Prowler script & reports.
  - [AWS CloudFormation](https://aws.amazon.com/cloudformation/), to provision the AWS resources.
  - [AWS Systems Manager Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html), Optional, but recommended, to manage the Prowler EC2 instance, without having to allow inbound ssh.
- Staying cohesive with Prowler, for scripting, only leveraging:
  - Bash Shell
  - AWS CLI
- Adhere to the principle of least privilege.
- Support an AWS Multi-Account approach
  - Runs Prowler against All accounts in the AWS Organization

---

## Components

1. [ProwlerS3.yaml](util\org-multi-account\ProwlerS3.yaml)
    - Creates Private S3 Bucket for Prowler script and reports.
    - Public Access Block permissions enabled.
    - SSE-S3 used for encryption
    - Versioning Enabled
    - Bucket Policy only grants GetObject, PutObject, and ListObject to Principals from the same AWS Organization.
1. [ProwlerRole.yaml](util\org-multi-account\ProwlerRole.yaml)
    - Creates Cross-Account Role for Prowler to assess accounts in AWS Organization
    - Allows Role to be assumed by the Prowler EC2 instance role in the AWS account where Prowler EC2 resides (preferably the Audit/Security account).
    - Role has [permissions](https://github.com/toniblyx/prowler#custom-iam-policy) needed for Prowler to assess accounts.
    - Role has GetObject, PutObject, and ListObject rights to Prowler S3 from Component #1.
1. [ProwlerEC2.yaml](util\org-multi-account\ProwlerEC2.yaml)
    - Creates Prowler EC2 instance
      - Uses the Latest Amazon Linux 2 AMI
      - Uses "t2.micro" Instance Type
    - Uses [cfn-init](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-init.html) for prepping the Prowler EC2
      - Installs necessary [packages](https://github.com/toniblyx/prowler#requirements-and-installation) for Prowler
      - Downloads [run-prowler-reports.sh](util\org-multi-account\src\run-prowler-reports.sh) script from Prowler S3 from Component #1.
      - Creates /home/ec2-user/.awsvariables, to store CloudFormation data as variables to be used in script.
      - Creates cron job for Prowler to run on a schedule.
    - Creates Prowler Security Group
      - Denies inbound access.  If using ssh to manage Prowler, then update Security Group with pertinent rule.
      - Allows outbound 80/443 for updates, and Amazon S3 communications
    - Creates Instance Role that is used for Prowler EC2
      - Role has permissions for [Systems Manager Agent](https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent.html) communications, and [Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html)
      - Role has GetObject, PutObject, and ListObject rights to Prowler S3 from Component #1.
      - Role has rights to Assume Cross-Account Role from Component #2.
1. [run-prowler-reports.sh](util\org-multi-account\src\run-prowler-reports.sh)
    - Script is documented accordingly.
    - In summary:
      - Download latest version of [Prowler ](https://github.com/toniblyx/prowler)
      - Find AWS Master Account
      - Lookup All Accounts in AWS Organization
      - Run Prowler against All Accounts in AWS Organization
      - Save Reports to reports prefix in S3 from Component #1
      - Report Names: date+time-accountid-report.html

---

## Instructions

1. Deploy [ProwlerS3.yaml](util\org-multi-account\ProwlerS3.yaml) in the Logging Account.
    - Could be deployed to any account in the AWS Organizations, if desired.
1. Upload [run-prowler-reports.sh](util\org-multi-account\src\run-prowler-reports.sh) to the root of the S3 Bucket created in Step #1.
1. Deploy [ProwlerRole.yaml](util\org-multi-account\ProwlerRole.yaml) in the Master Account
    - Use CloudFormation Stacks, to deploy to Master Account, as organizational StackSets don't apply to the Master Account.
    - Use CloudFormation StackSet, to deploy to all Member Accounts.
1. Deploy [ProwlerEC2.yaml](util\org-multi-account\ProwlerEC2.yaml) in the Audit/Security Account
    - Could be deployed to any account in the AWS Organizations, if desired.
1. Scheduled: Run Prowler against all Accounts in AWS Organization, based on schedule you provided, and set for the cron job.
1. Adhoc: Run Prowler against all Accounts in AWS Organization
    - Connect to Prowler EC2 Instance
      - If using Session Manager, then after login, switch to "ec2-user", via:  sudo -u ec2-user
      - If using SSH, then login as "ec2-user"
    - Run Script:  /home/ec2-user/run-prowler-reports.sh
