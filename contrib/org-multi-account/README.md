# Example Solution:  Organizational Prowler Deployment

Deploys [Prowler](https://github.com/prowler-cloud/prowler) to assess all Accounts in an AWS Organization on a schedule, creates assessment reports in HTML, and stores them in an S3 bucket.

---

## Example Solution Goals

- Using minimal technologies, so solution can be more easily adopted, and further enhanced as needed.
  - [Amazon EC2](https://aws.amazon.com/ec2/), to run Prowler
  - [Amazon S3](https://aws.amazon.com/s3/), to store Prowler script & reports.
  - [AWS CloudFormation](https://aws.amazon.com/cloudformation/), to provision the AWS resources.
  - [AWS Systems Manager Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html), Optional, but recommended, to manage the Prowler EC2 instance, without having to allow inbound ssh.
- Staying cohesive with Prowler, for scripting, only leveraging:
  - Bash Shell
  - AWS CLI
- Adhering to the principle of least privilege.
- Supporting an AWS Multi-Account approach
  - Runs Prowler against All accounts in the AWS Organization
- ***NOTE: If using this solution, you are responsible for making your own independent assessment of the solution and ensuring it complies with your company security and operational standards.***

---

## Components

1. [ProwlerS3.yaml](ProwlerS3.yaml)
    - Creates Private S3 Bucket for Prowler script and reports.
    - Enables [Amazon S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html)
    - Enables SSE-S3 with [Amazon S3 Default Encryption](https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html)
    - Versioning Enabled
    - Bucket Policy limits API actions to Principals from the same AWS Organization.
1. [ProwlerRole.yaml](ProwlerRole.yaml)
    - Creates Cross-Account Role for Prowler to assess accounts in AWS Organization
    - Allows Role to be assumed by the Prowler EC2 instance role in the AWS account where Prowler EC2 resides (preferably the Audit/Security account).
    - Role has [permissions](https://github.com/prowler-cloud/prowler#custom-iam-policy) needed for Prowler to assess accounts.
    - Role has rights to Prowler S3 from Component #1.
1. [ProwlerEC2.yaml](ProwlerEC2.yaml)
    - Creates Prowler EC2 instance
      - Uses the Latest Amazon Linux 2 AMI
      - Uses ```t2.micro``` Instance Type
      - Encrypts Root Volume with AWS Managed Key "aws/ebs"
    - Uses [cfn-init](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-init.html) for prepping the Prowler EC2
      - Installs necessary [packages](https://github.com/prowler-cloud/prowler#requirements-and-installation) for Prowler
      - Downloads [run-prowler-reports.sh](src/run-prowler-reports.sh) script from Prowler S3 from Component #1.
      - Creates ```/home/ec2-user/.awsvariables```, to store CloudFormation data as variables to be used in script.
      - Creates cron job for Prowler to run on a schedule.
    - Creates Prowler Security Group
      - Denies inbound access.  If using ssh to manage Prowler, then update Security Group with pertinent rule.
      - Allows outbound 80/443 for updates, and Amazon S3 communications      -
    - Creates Instance Role that is used for Prowler EC2
      - Role has permissions for [Systems Manager Agent](https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent.html) communications, and [Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html)
      - Role has rights to Prowler S3 from Component #1.
      - Role has rights to Assume Cross-Account Role from Component #2.
1. [run-prowler-reports.sh](src/run-prowler-reports.sh)
    - Script is documented accordingly.
    - Script loops through all AWS Accounts in AWS Organization, and by default, Runs Prowler as follows:
      - -R: used to specify Cross-Account role for Prowler to assume to run its assessment.
      - -A: used to specify AWS Account number for Prowler to run assessment against.
      - -g cislevel1: used to specify cislevel1 checks for Prowler to assess

        ```bash
        ./prowler/prowler -R "$ROLE" -A "$accountId" -g cislevel1 -M html
        ```

      - NOTE: Script can be modified to run Prowler as desired.
    - Script runs Prowler against 1 AWS Account at a time.
      - Update PARALLEL_ACCOUNTS variable in script, to specify how many Accounts to assess with Prowler in parallel.
      - If running against multiple AWS Accounts in parallel, monitor performance, and upgrade Instance Type as necessary.

        ```bash
        PARALLEL_ACCOUNTS="1"
        ```

    - In summary:
      - Download latest version of [Prowler](https://github.com/prowler-cloud/prowler)
      - Find AWS Master Account
      - Lookup All Accounts in AWS Organization
      - Run Prowler against All Accounts in AWS Organization
      - Save Reports to reports prefix in S3 from Component #1
      - Report Names: date+time-accountid-report.html

---

## Instructions

1. Deploy [ProwlerS3.yaml](ProwlerS3.yaml) in the Logging Account.
    - Could be deployed to any account in the AWS Organizations, if desired.
    - See [How to get AWS Organization ID](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_details.html#orgs_view_org)
    - Take Note of CloudFormation Outputs, that will be needed in deploying the below CloudFormation templates.
1. Upload [run-prowler-reports.sh](src/run-prowler-reports.sh) to the root of the S3 Bucket created in Step #1.
1. Deploy [ProwlerRole.yaml](ProwlerRole.yaml) in the Master Account
    - Use CloudFormation Stacks, to deploy to Master Account, as organizational StackSets don't apply to the Master Account.
    - Use CloudFormation StackSet, to deploy to all Member Accounts. See [Create Stack Set with Service-Managed Permissions](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-getting-started-create.html#stacksets-orgs-associate-stackset-with-org)
    - Take Note of CloudFormation Outputs, that will be needed in deploying the below CloudFormation templates.
1. Deploy [ProwlerEC2.yaml](ProwlerEC2.yaml) in the Audit/Security Account
    - Could be deployed to any account in the AWS Organizations, if desired.
1. Prowler will run against all Accounts in AWS Organization, per the schedule you provided, and set in a cron job for ```ec2-user```

---

## Post-Setup

### Run Prowler on a Schedule against all Accounts in AWS Organization

1. Prowler will run on the Schedule you provided.
1. Cron job for ```ec2-user``` is managing the schedule.
1. This solution implemented this automatically. Nothing for you to do.

### Ad hoc Run Prowler against all Accounts in AWS Organization

1. Connect to Prowler EC2 Instance
    - If using Session Manager, then after login, switch to ```ec2-user```, via: ```sudo bash``` and ```su - ec2-user```
    - If using SSH, then login as ```ec2-user```
1. Run Prowler Script

    ```bash
    cd /home/ec2-user
    ./run-prowler-reports.sh
    ```

### Ad hoc Run Prowler Interactively

1. Connect to Prowler EC2 Instance
    - If using Session Manager, then after login, switch to ```ec2-user```, via: ```sudo bash``` and ```su - ec2-user```
    - If using SSH, then login as ```ec2-user```
1. See Cross-Account Role and S3 Bucket being used for Prowler

      ```bash
      cd /home/ec2-user
      cat .awsvariables
      ```

1. Run Prowler interactively. See [Usage Examples](https://github.com/prowler-cloud/prowler#usage)

      ```bash
      cd /home/ec2-user
      ./prowler/prowler
      ```

### Upgrading Prowler to Latest Version

1. Connect to Prowler EC2 Instance
    - If using Session Manager, then after login, switch to ```ec2-user```, via: ```sudo bash``` and ```su - ec2-user```
    - If using SSH, then login as ```ec2-user```
1. Delete the existing version of Prowler, and download the latest version of Prowler

    ```bash
    cd /home/ec2-user
    rm -rf prowler
    git clone https://github.com/prowler-cloud/prowler.git
    ```
