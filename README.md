<p align="center">
  <img align="center" src="docs/images/prowler-pro-dark.png#gh-dark-mode-only" width="150" height="36">
  <img align="center" src="docs/images/prowler-pro-light.png#gh-light-mode-only" width="15%" height="15%">
</p>
<p align="center">
  <b><i>&nbsp&nbsp&nbsp See all the things you and your team can do with ProwlerPro at <a href="https://prowler.pro">prowler.pro</a></i></b>
</p>
<hr>
<p align="center">
  <img src="https://user-images.githubusercontent.com/3985464/113734260-7ba06900-96fb-11eb-82bc-d4f68a1e2710.png" />
</p>
<p align="center">
  <a href="https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog"><img alt="Slack Shield" src="https://img.shields.io/badge/slack-prowler-brightgreen.svg?logo=slack"></a>
  <a href="https://hub.docker.com/r/toniblyx/prowler"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/toniblyx/prowler"></a>
  <a href="https://hub.docker.com/r/toniblyx/prowler"><img alt="Docker" src="https://img.shields.io/docker/cloud/build/toniblyx/prowler"></a>
  <a href="https://hub.docker.com/r/toniblyx/prowler"><img alt="Docker" src="https://img.shields.io/docker/image-size/toniblyx/prowler"></a>
  <a href="https://gallery.ecr.aws/o4g1s5r6/prowler"><img width="120" height=19" alt="AWS ECR Gallery" src="https://user-images.githubusercontent.com/3985464/151531396-b6535a68-c907-44eb-95a1-a09508178616.png"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="Repo size" src="https://img.shields.io/github/repo-size/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="Lines" src="https://img.shields.io/tokei/lines/github/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler/issues"><img alt="Issues" src="https://img.shields.io/github/issues/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler/releases"><img alt="Version" src="https://img.shields.io/github/v/release/prowler-cloud/prowler?include_prereleases"></a>
  <a href="https://github.com/prowler-cloud/prowler/releases"><img alt="Version" src="https://img.shields.io/github/release-date/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="Contributors" src="https://img.shields.io/github/contributors-anon/prowler-cloud/prowler"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="License" src="https://img.shields.io/github/license/prowler-cloud/prowler"></a>
  <a href="https://twitter.com/ToniBlyx"><img alt="Twitter" src="https://img.shields.io/twitter/follow/toniblyx?style=social"></a>
</p>

<p align="center">
  <i>Prowler</i> is an Open Source security tool to perform AWS security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness. It contains more than 240 controls covering CIS, PCI-DSS, ISO27001, GDPR, HIPAA, FFIEC, SOC2, AWS FTR, ENS and custom security frameworks.
</p>

## Table of Contents

- [Description](#description)
- [Prowler Container Versions](#prowler-container-versions)
- [Features](#features)
- [High level architecture](#high-level-architecture)
- [Requirements and Installation](#requirements-and-installation)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [Advanced Usage](#advanced-usage)
- [Security Hub integration](#security-hub-integration)
- [CodeBuild deployment](#codebuild-deployment)
- [Allowlist](#allowlist-or-remove-a-fail-from-resources)
- [Inventory](#inventory)
- [Fix](#how-to-fix-every-fail)
- [Troubleshooting](#troubleshooting)
- [Extras](#extras)
- [Forensics Ready Checks](#forensics-ready-checks)
- [GDPR Checks](#gdpr-checks)
- [HIPAA Checks](#hipaa-checks)
- [Trust Boundaries Checks](#trust-boundaries-checks)
- [Multi Account and Continuous Monitoring](util/org-multi-account/README.md)
- [Custom Checks](#custom-checks)
- [Third Party Integrations](#third-party-integrations)
- [Full list of checks and groups](/LIST_OF_CHECKS_AND_GROUPS.md)
- [License](#license)

## Description

Prowler is a command line tool that helps you with AWS security assessment, auditing, hardening and incident response.

It follows guidelines of the CIS Amazon Web Services Foundations Benchmark (49 checks) and has more than 190 additional checks including related to GDPR, HIPAA, PCI-DSS, ISO-27001, FFIEC, SOC2 and others.

Read more about [CIS Amazon Web Services Foundations Benchmark v1.2.0 - 05-23-2018](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf)

## Prowler container versions

The available versions of Prowler are the following:
- latest: in sync with master branch (bear in mind that it is not a stable version)
- <x.y.z> (release): you can find the releases [here](https://github.com/prowler-cloud/prowler/releases), those are stable releases.
- stable: this tag always point to the latest release.  

The container images are available here:
- [DockerHub](https://hub.docker.com/r/toniblyx/prowler/tags)
- [AWS Public ECR](https://gallery.ecr.aws/o4g1s5r6/prowler)

## Features

+240 checks covering security best practices across all AWS regions and most of AWS services and related to the next groups:

- Identity and Access Management [group1]
- Logging [group2]
- Monitoring [group3]
- Networking [group4]
- CIS Level 1 [cislevel1]
- CIS Level 2 [cislevel2]
- Extras _see Extras section_ [extras]
- Forensics related group of checks [forensics-ready]
- GDPR [gdpr] Read more [here](#gdpr-checks)
- HIPAA [hipaa] Read more [here](#hipaa-checks)
- Trust Boundaries [trustboundaries] Read more [here](#trust-boundaries-checks)
- Secrets
- Internet exposed resources
- EKS-CIS
- Also includes PCI-DSS, ISO-27001, FFIEC, SOC2, ENS (Esquema Nacional de Seguridad of Spain).
- AWS FTR [FTR] Read more [here](#aws-ftr-checks)

With Prowler you can:

- Get a direct colorful or monochrome report
- A HTML, CSV, JUNIT, JSON or JSON ASFF (Security Hub) format report
- Send findings directly to the Security Hub
- Run specific checks and groups or create your own
- Check multiple AWS accounts in parallel or sequentially
- Get an inventory of your AWS resources
- And more! Read examples below

## High level architecture

You can run Prowler from your workstation, an EC2 instance, Fargate or any other container, Codebuild, CloudShell and Cloud9.

![Prowler high level architecture](https://user-images.githubusercontent.com/3985464/109143232-1488af80-7760-11eb-8d83-726790fda592.jpg)

## Requirements and Installation

Prowler has been written in bash using AWS-CLI underneath and it works in Linux, Mac OS or Windows with cygwin or virtualization. Also requires `jq` and `detect-secrets` to work properly.

- Make sure the latest version of AWS-CLI is installed. It works with either v1 or v2, however _latest v2 is recommended if using new regions since they require STS v2 token_, and other components needed, with Python pip already installed.

- For Amazon Linux (`yum` based Linux distributions and AWS CLI v2):
  ```
  sudo yum update -y
  sudo yum remove -y awscli
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip awscliv2.zip
  sudo ./aws/install
  sudo yum install -y python3 jq git
  sudo pip3 install detect-secrets==1.0.3
  git clone https://github.com/prowler-cloud/prowler
  ```
- For Ubuntu Linux (`apt` based Linux distributions and AWS CLI v2):

  ```
  sudo apt update
  sudo apt install python3 python3-pip jq git zip
  pip install detect-secrets==1.0.3
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip awscliv2.zip
  sudo ./aws/install
  git clone https://github.com/prowler-cloud/prowler
  ```

  > NOTE: detect-secrets Yelp version is no longer supported, the one from IBM is mantained now. Use the one mentioned below or the specific Yelp version 1.0.3 to make sure it works as expected (`pip install detect-secrets==1.0.3`):

  ```sh
  pip install "git+https://github.com/ibm/detect-secrets.git@master#egg=detect-secrets"
  ```

  AWS-CLI can be also installed it using other methods, refer to official documentation for more details: <https://aws.amazon.com/cli/>, but `detect-secrets` has to be installed using `pip` or `pip3`.

- Once Prowler repository is cloned, get into the folder and you can run it:

  ```sh
  cd prowler
  ./prowler
  ```

- Since Prowler users AWS CLI under the hood, you can follow any authentication method as described [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-precedence). Make sure you have properly configured your AWS-CLI with a valid Access Key and Region or declare AWS variables properly (or instance profile/role):

  ```sh
  aws configure
  ```

  or

  ```sh
  export AWS_ACCESS_KEY_ID="ASXXXXXXX"
  export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
  export AWS_SESSION_TOKEN="XXXXXXXXX"
  ```

- Those credentials must be associated to a user or role with proper permissions to do all checks. To make sure, add the AWS managed policies, SecurityAudit and ViewOnlyAccess, to the user or role being used. Policy ARNs are:

  ```sh
  arn:aws:iam::aws:policy/SecurityAudit
  arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
  ```

  > Additional permissions needed: to make sure Prowler can scan all services included in the group _Extras_, make sure you attach also the custom policy [prowler-additions-policy.json](https://github.com/prowler-cloud/prowler/blob/master/iam/prowler-additions-policy.json) to the role you are using. If you want Prowler to send findings to [AWS Security Hub](https://aws.amazon.com/security-hub), make sure you also attach the custom policy [prowler-security-hub.json](https://github.com/prowler-cloud/prowler/blob/master/iam/prowler-security-hub.json).

## Usage

1. Run the `prowler` command without options (it will use your environment variable credentials if they exist or will default to using the `~/.aws/credentials` file and run checks over all regions when needed. The default region is us-east-1):

   ```sh
   ./prowler
   ```

   Use `-l` to list all available checks and the groups (sections) that reference them. To list all groups use `-L` and to list content of a group use `-l -g <groupname>`.

   If you want to avoid installing dependencies run it using Docker:

   ```sh
   docker run -ti --rm --name prowler --env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY --env AWS_SESSION_TOKEN toniblyx/prowler:latest
   ```

   In case you want to get reports created by Prowler use docker volume option like in the example below:

   ```sh
   docker run -ti --rm -v /your/local/output:/prowler/output --name prowler --env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY --env AWS_SESSION_TOKEN toniblyx/prowler:latest -g hipaa -M csv,json,html
   ```

1. For custom AWS-CLI profile and region, use the following: (it will use your custom profile and run checks over all regions when needed):

   ```sh
   ./prowler -p custom-profile -r us-east-1
   ```

1. For a single check use option `-c`:

   ```sh
   ./prowler -c check310
   ```

   With Docker:

   ```sh
   docker run -ti --rm --name prowler --env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY --env AWS_SESSION_TOKEN toniblyx/prowler:latest "-c check310"
   ```

   or multiple checks separated by comma:

   ```sh
   ./prowler -c check310,check722
   ```

   or all checks but some of them:

   ```sh
   ./prowler -E check42,check43
   ```

   or for custom profile and region:

   ```sh
   ./prowler -p custom-profile -r us-east-1 -c check11
   ```

   or for a group of checks use group name:

   ```sh
   ./prowler -g group1 # for iam related checks
   ```

   or exclude some checks in the group:

   ```sh
   ./prowler -g group4 -E check42,check43
   ```

   Valid check numbers are based on the AWS CIS Benchmark guide, so 1.1 is check11 and 3.10 is check310

### Regions

By default, Prowler scans all opt-in regions available, that might take a long execution time depending on the number of resources and regions used. Same applies for GovCloud or China regions. See below Advance usage for examples.

Prowler has two parameters related to regions: `-r` that is used query AWS services API endpoints (it uses `us-east-1` by default and required for GovCloud or China) and the option `-f` that is to filter those regions you only want to scan. For example if you want to scan Dublin only use `-f eu-west-1` and if you want to scan Dublin and Ohio `-f eu-west-1,us-east-1`, note the regions are separated by a comma delimiter (it can be used as before with `-f 'eu-west-1,us-east-1'`).

## Screenshots

- Sample screenshot of default console report first lines of command `./prowler`:

    <img width="900" src="https://user-images.githubusercontent.com/3985464/141444529-84640bed-be0b-4112-80a2-2a43e3ebf53f.png">

- Sample screenshot of the html output `-M html`:

    <img width="900" alt="Prowler html" src="https://user-images.githubusercontent.com/3985464/141443976-41d32cc2-533d-405a-92cb-affc3995d6ec.png">

- Sample screenshot of the Quicksight dashboard, see [quicksight-security-dashboard.workshop.aws](https://quicksight-security-dashboard.workshop.aws/):

    <img width="900" alt="Prowler with Quicksight" src="https://user-images.githubusercontent.com/3985464/128932819-0156e838-286d-483c-b953-fda68a325a3d.png">

- Sample screenshot of the junit-xml output in CodeBuild `-M junit-xml`:

    <img width="900" src="https://user-images.githubusercontent.com/3985464/113942824-ca382b00-9801-11eb-84e5-d7731548a7a9.png">

### Save your reports

1. If you want to save your report for later analysis thare are different ways, natively (supported text, mono, csv, json, json-asff, junit-xml and html, see note below for more info):

   ```sh
   ./prowler -M csv
   ```

   or with multiple formats at the same time:

   ```sh
   ./prowler -M csv,json,json-asff,html
   ```

   or just a group of checks in multiple formats:

   ```sh
   ./prowler -g gdpr -M csv,json,json-asff
   ```

   or if you want a sorted and dynamic HTML report do:

   ```sh
   ./prowler -M html
   ```

   Now `-M` creates a file inside the prowler `output` directory named `prowler-output-AWSACCOUNTID-YYYYMMDDHHMMSS.format`. You don't have to specify anything else, no pipes, no redirects.

   or just saving the output to a file like below:

   ```sh
   ./prowler -M mono > prowler-report.txt
   ```

   To generate JUnit report files, include the junit-xml format. This can be combined with any other format. Files are written inside a prowler root directory named `junit-reports`:

   ```sh
   ./prowler -M text,junit-xml
   ```

   > Note about output formats to use with `-M`: "text" is the default one with colors, "mono" is like default one but monochrome, "csv" is comma separated values, "json" plain basic json (without comma between lines) and "json-asff" is also json with Amazon Security Finding Format that you can ship to Security Hub using `-S`.

   To save your report in an S3 bucket, use `-B` to define a custom output bucket along with `-M` to define the output format that is going to be uploaded to S3:

   ```sh
   ./prowler -M csv -B my-bucket/folder/
   ```

   > In the case you do not want to use the assumed role credentials but the initial credentials to put the reports into the S3 bucket, use `-D` instead of `-B`. Make sure that the used credentials have s3:PutObject permissions in the S3 path where the reports are going to be uploaded.

   When generating multiple formats and running using Docker, to retrieve the reports, bind a local directory to the container, e.g.:

   ```sh
   docker run -ti --rm --name prowler --volume "$(pwd)":/prowler/output --env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY --env AWS_SESSION_TOKEN toniblyx/prowler:latest -M csv,json
   ```

1. To perform an assessment based on CIS Profile Definitions you can use cislevel1 or cislevel2 with `-g` flag, more information about this [here, page 8](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf):

   ```sh
   ./prowler -g cislevel1
   ```

1. If you want to run Prowler to check multiple AWS accounts in parallel (runs up to 4 simultaneously `-P 4`) but you may want to read below in Advanced Usage section to do so assuming a role:

   ```sh
   grep -E '^\[([0-9A-Aa-z_-]+)\]'  ~/.aws/credentials | tr -d '][' | shuf |  \
   xargs -n 1 -L 1 -I @ -r -P 4 ./prowler -p @ -M csv  2> /dev/null  >> all-accounts.csv
   ```

1. For help about usage run:

   ```
   ./prowler -h
   ```

## Database providers connector

You can send the Prowler's output to different databases (right now only PostgreSQL is supported).

Jump into the section for the database provider you want to use and follow the required steps to configure it.

### PostgreSQL

Install psql

- Mac -> `brew install libpq`
- Ubuntu -> `sudo apt-get install postgresql-client `
- RHEL/Centos -> `sudo yum install postgresql10`

#### Audit ID Field

To use Prowler postgres connector it is needed to set the -u flag to include  `audit_id` field into the query. This field helps to identify each audit that has been made in the database. This field needs to be an UUID V4 to match the table schema.
For example:  
```
./prowler -M csv -d postgresql -u e5a0f214-8bf9-4600-a0c3-ff659b30e6c0
```

#### Credentials

There are two options to pass the PostgreSQL credentials to Prowler:

##### Using a .pgpass file

Configure a `~/.pgpass` file into the root folder of the user that is going to launch Prowler ([pgpass file doc](https://www.postgresql.org/docs/current/libpq-pgpass.html)), including an extra field at the end of the line, separated by `:`, to name the table, using the following format:
`hostname:port:database:username:password:table`

##### Using environment variables

- Configure the following environment variables:  
   - `POSTGRES_HOST`  
   - `POSTGRES_PORT`  
   - `POSTGRES_USER`  
   - `POSTGRES_PASSWORD`  
   - `POSTGRES_DB`  
   - `POSTGRES_TABLE`
  > _Note_: If you are using a schema different than postgres please include it at the beginning of the `POSTGRES_TABLE` variable, like: `export POSTGRES_TABLE=prowler.findings`

Also you need to have enabled the `uuid` postgresql extension, to enable it:

`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`

Create a table in your PostgreSQL database to store the Prowler's data. You can use the following SQL statement to create the table:

```
CREATE TABLE  IF NOT EXISTS prowler_findings (
id uuid,
audit_id uuid ,
profile text,
account_number text,
region text,
check_id text,
result text,
item_scored text,
item_level text,
check_title text,
result_extended text,
check_asff_compliance_type text,
severity text,
service_name text,
check_asff_resource_type text,
check_asff_type text,
risk text,
remediation text,
documentation text,
check_caf_epic text,
resource_id text,
account_details_email text,
account_details_name text,
account_details_arn text,
account_details_org text,
account_details_tags text,
prowler_start_time text
);
```

- Execute Prowler with `-d` flag, for example:
  `./prowler -M csv -d postgresql -u e5a0f214-8bf9-4600-a0c3-ff659b30e6c0`
  > _Note_: This command creates a `csv` output file and stores the Prowler output in the configured PostgreSQL DB. It's an example, `-d` flag **does not** require `-M` to run.

## Output Formats

Prowler supports natively the following output formats:

- CSV
- JSON
- JSON-ASFF
- HTML
- JUNIT-XML

Hereunder is the structure for each of them

### CSV

| PROFILE | ACCOUNT_NUM | REGION | TITLE_ID | CHECK_RESULT | ITEM_SCORED | ITEM_LEVEL | TITLE_TEXT | CHECK_RESULT_EXTENDED | CHECK_ASFF_COMPLIANCE_TYPE | CHECK_SEVERITY | CHECK_SERVICENAME | CHECK_ASFF_RESOURCE_TYPE | CHECK_ASFF_TYPE | CHECK_RISK | CHECK_REMEDIATION | CHECK_DOC | CHECK_CAF_EPIC | CHECK_RESOURCE_ID | PROWLER_START_TIME | ACCOUNT_DETAILS_EMAIL | ACCOUNT_DETAILS_NAME | ACCOUNT_DETAILS_ARN | ACCOUNT_DETAILS_ORG | ACCOUNT_DETAILS_TAGS |
| ------- | ----------- | ------ | -------- | ------------ | ----------- | ---------- | ---------- | --------------------- | -------------------------- | -------------- | ----------------- | ------------------------ | --------------- | ---------- | ----------------- | --------- | -------------- | ----------------- | ------------------ | --------------------- | -------------------- | ------------------- | ------------------- | -------------------- |

### JSON

```
{
  "Profile": "ENV",
  "Account Number": "1111111111111",
  "Control": "[check14] Ensure access keys are rotated every 90 days or less",
  "Message": "us-west-2: user has not rotated access key 2 in over 90 days",
  "Severity": "Medium",
  "Status": "FAIL",
  "Scored": "",
  "Level": "CIS Level 1",
  "Control ID": "1.4",
  "Region": "us-west-2",
  "Timestamp": "2022-05-18T10:33:48Z",
  "Compliance": "ens-op.acc.1.aws.iam.4 ens-op.acc.5.aws.iam.3",
  "Service": "iam",
  "CAF Epic": "IAM",
  "Risk": "Access keys consist of an access key ID and secret access key which are used to sign programmatic requests that you make to AWS. AWS users need their own access keys to make programmatic calls to AWS from the AWS Command Line Interface (AWS CLI)- Tools for Windows PowerShell- the AWS SDKs- or direct HTTP calls using the APIs for individual AWS services. It is recommended that all access keys be regularly rotated.",
  "Remediation": "Use the credential report to  ensure  access_key_X_last_rotated  is less than 90 days ago.",
  "Doc link": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html",
  "Resource ID": "terraform-user",
  "Account Email": "",
  "Account Name": "",
  "Account ARN": "",
  "Account Organization": "",
  "Account tags": ""
}
```

> NOTE: Each finding is a `json` object.

### JSON-ASFF

```
{
  "SchemaVersion": "2018-10-08",
  "Id": "prowler-1.4-1111111111111-us-west-2-us-west-2_user_has_not_rotated_access_key_2_in_over_90_days",
  "ProductArn": "arn:aws:securityhub:us-west-2::product/prowler/prowler",
  "RecordState": "ACTIVE",
  "ProductFields": {
    "ProviderName": "Prowler",
    "ProviderVersion": "2.9.0-13April2022",
    "ProwlerResourceName": "user"
  },
  "GeneratorId": "prowler-check14",
  "AwsAccountId": "1111111111111",
  "Types": [
    "ens-op.acc.1.aws.iam.4 ens-op.acc.5.aws.iam.3"
  ],
  "FirstObservedAt": "2022-05-18T10:33:48Z",
  "UpdatedAt": "2022-05-18T10:33:48Z",
  "CreatedAt": "2022-05-18T10:33:48Z",
  "Severity": {
    "Label": "MEDIUM"
  },
  "Title": "iam.[check14] Ensure access keys are rotated every 90 days or less",
  "Description": "us-west-2: user has not rotated access key 2 in over 90 days",
  "Resources": [
    {
      "Type": "AwsIamUser",
      "Id": "user",
      "Partition": "aws",
      "Region": "us-west-2"
    }
  ],
  "Compliance": {
    "Status": "FAILED",
    "RelatedRequirements": [
      "ens-op.acc.1.aws.iam.4 ens-op.acc.5.aws.iam.3"
    ]
  }
}
```

> NOTE: Each finding is a `json` object.

## Advanced Usage

### Assume Role:

Prowler uses the AWS CLI underneath so it uses the same authentication methods. However, there are few ways to run Prowler against multiple accounts using IAM Assume Role feature depending on eachg use case. You can just set up your custom profile inside `~/.aws/config` with all needed information about the role to assume then call it with `./prowler -p your-custom-profile`. Additionally you can use `-A 123456789012` and `-R RemoteRoleToAssume` and Prowler will get those temporary credentials using `aws sts assume-role`, set them up as environment variables and run against that given account. To create a role to assume in multiple accounts easier either as CFN Stack or StackSet, look at [this CloudFormation template](iam/create_role_to_assume_cfn.yaml) and adapt it.

```sh
./prowler -A 123456789012 -R ProwlerRole
```

```sh
./prowler -A 123456789012 -R ProwlerRole -I 123456
```

> _NOTE 1 about Session Duration_: By default it gets credentials valid for 1 hour (3600 seconds). Depending on the mount of checks you run and the size of your infrastructure, Prowler may require more than 1 hour to finish. Use option `-T <seconds>` to allow up to 12h (43200 seconds). To allow more than 1h you need to modify _"Maximum CLI/API session duration"_ for that particular role, read more [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html#id_roles_use_view-role-max-session).

> _NOTE 2 about Session Duration_: Bear in mind that if you are using roles assumed by role chaining there is a hard limit of 1 hour so consider not using role chaining if possible, read more about that, in foot note 1 below the table [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html).

For example, if you want to get only the fails in CSV format from all checks regarding RDS without banner from the AWS Account 123456789012 assuming the role RemoteRoleToAssume and set a fixed session duration of 1h:

```sh
./prowler -A 123456789012 -R RemoteRoleToAssume -T 3600 -b -M cvs -q -g rds
```

or with a given External ID:

```sh
./prowler -A 123456789012 -R RemoteRoleToAssume -T 3600 -I 123456 -b -M cvs -q -g rds
```

### Assume Role and across all accounts in AWS Organizations or just a list of accounts:

If you want to run Prowler or just a check or a group across all accounts of AWS Organizations you can do this:

First get a list of accounts that are not suspended:

```
ACCOUNTS_IN_ORGS=$(aws organizations list-accounts --query Accounts[?Status==`ACTIVE`].Id --output text)
```

Then run Prowler to assume a role (same in all members) per each account, in this example it is just running one particular check:

```
for accountId in $ACCOUNTS_IN_ORGS; do ./prowler -A $accountId -R RemoteRoleToAssume -c extra79; done
```

Using the same for loop it can be scanned a list of accounts with a variable like `ACCOUNTS_LIST='11111111111 2222222222 333333333'`

### Get AWS Account details from your AWS Organization:

From Prowler v2.8, you can get additional information of the scanned account in CSV and JSON outputs. When scanning a single account you get the Account ID as part of the output. Now, if you have AWS Organizations and are scanning multiple accounts using the assume role functionality, Prowler can get your account details like Account Name, Email, ARN, Organization ID and Tags and you will have them next to every finding in the CSV and JSON outputs.
In order to do that you can use the new option `-O <management account id>`, requires `-R <role to assume>` and also needs permissions `organizations:ListAccounts*` and `organizations:ListTagsForResource`. See the following sample command:

```
./prowler -R ProwlerScanRole -A 111111111111 -O 222222222222 -M json,csv
```

In that command Prowler will scan the account `111111111111` assuming the role `ProwlerScanRole` and getting the account details from the AWS Organizatiosn management account `222222222222` assuming the same role `ProwlerScanRole` for that and creating two reports with those details in JSON and CSV.

In the JSON output below (redacted) you can see tags coded in base64 to prevent breaking CSV or JSON due to its format:

```json
  "Account Email": "my-prod-account@domain.com",
  "Account Name": "my-prod-account",
  "Account ARN": "arn:aws:organizations::222222222222:account/o-abcde1234/111111111111",
  "Account Organization": "o-abcde1234",
  "Account tags": "\"eyJUYWdzIjpasf0=\""
```

The additional fields in CSV header output are as follow:

```csv
ACCOUNT_DETAILS_EMAIL,ACCOUNT_DETAILS_NAME,ACCOUNT_DETAILS_ARN,ACCOUNT_DETAILS_ORG,ACCOUNT_DETAILS_TAGS
```

### GovCloud

Prowler runs in GovCloud regions as well. To make sure it points to the right API endpoint use `-r` to either `us-gov-west-1` or `us-gov-east-1`. If not filter region is used it will look for resources in both GovCloud regions by default:

```sh
./prowler -r us-gov-west-1
```

> For Security Hub integration see below in Security Hub section.

### Custom folder for custom checks

Flag `-x /my/own/checks` will include any check in that particular directory (files must start by check). To see how to write checks see [Add Custom Checks](#add-custom-checks) section.

S3 URIs are also supported as custom folders for custom checks, e.g. `s3://bucket/prefix/checks`. Prowler will download the folder locally and run the checks as they are called with default execution,`-c` or `-g`.

> Make sure that the used credentials have s3:GetObject permissions in the S3 path where the custom checks are located.

### Show or log only FAILs

In order to remove noise and get only FAIL findings there is a `-q` flag that makes Prowler to show and log only FAILs.
It can be combined with any other option.
Will show WARNINGS when a resource is excluded, just to take into consideration.

```sh
# -q option combined with -M csv -b
./prowler -q -M csv -b
```

### Set the entropy limit for detect-secrets

Sets the entropy limit for high entropy base64 strings from environment variable `BASE64_LIMIT`. Value must be between 0.0 and 8.0, defaults is 4.5.
Sets the entropy limit for high entropy hex strings from environment variable `HEX_LIMIT`. Value must be between 0.0 and 8.0, defaults is 3.0.

```sh
export BASE64_LIMIT=4.5
export HEX_LIMIT=3.0
```

### Run Prowler using AWS CloudShell

An easy way to run Prowler to scan your account is using AWS CloudShell. Read more and learn how to do it [here](util/cloudshell/README.md).

## Security Hub integration

Since October 30th 2020 (version v2.3RC5), Prowler supports natively and as **official integration** sending findings to [AWS Security Hub](https://aws.amazon.com/security-hub). This integration allows Prowler to import its findings to AWS Security Hub. With Security Hub, you now have a single place that aggregates, organizes, and prioritizes your security alerts, or findings, from multiple AWS services, such as Amazon GuardDuty, Amazon Inspector, Amazon Macie, AWS Identity and Access Management (IAM) Access Analyzer, and AWS Firewall Manager, as well as from AWS Partner solutions and from Prowler for free.

Before sending findings to Prowler, you need to perform next steps:

1. Since Security Hub is a region based service, enable it in the region or regions you require. Use the AWS Management Console or using the AWS CLI with this command if you have enough permissions:
   - `aws securityhub enable-security-hub --region <region>`.
2. Enable Prowler as partner integration integration. Use the AWS Management Console or using the AWS CLI with this command if you have enough permissions:
   - `aws securityhub enable-import-findings-for-product --region <region> --product-arn arn:aws:securityhub:<region>::product/prowler/prowler` (change region also inside the ARN).
   - Using the AWS Management Console:
     ![Screenshot 2020-10-29 at 10 26 02 PM](https://user-images.githubusercontent.com/3985464/97634660-5ade3400-1a36-11eb-9a92-4a45cc98c158.png)
3. As mentioned in section "Custom IAM Policy", to allow Prowler to import its findings to AWS Security Hub you need to add the policy below to the role or user running Prowler:
   - [iam/prowler-security-hub.json](iam/prowler-security-hub.json)

Once it is enabled, it is as simple as running the command below (for all regions):

```sh
./prowler -M json-asff -S
```

or for only one filtered region like eu-west-1:

```sh
./prowler -M json-asff -q -S -f eu-west-1
```

> Note 1: It is recommended to send only fails to Security Hub and that is possible adding `-q` to the command.

> Note 2: Since Prowler perform checks to all regions by defaults you may need to filter by region when runing Security Hub integration, as shown in the example above. Remember to enable Security Hub in the region or regions you need by calling `aws securityhub enable-security-hub --region <region>` and run Prowler with the option `-f <region>` (if no region is used it will try to push findings in all regions hubs).

> Note 3: to have updated findings in Security Hub you have to run Prowler periodically. Once a day or every certain amount of hours.

Once you run findings for first time you will be able to see Prowler findings in Findings section:

![Screenshot 2020-10-29 at 10 29 05 PM](https://user-images.githubusercontent.com/3985464/97634676-66c9f600-1a36-11eb-9341-70feb06f6331.png)

### Security Hub in GovCloud regions

To use Prowler and Security Hub integration in GovCloud there is an additional requirement, usage of `-r` is needed to point the API queries to the right API endpoint. Here is a sample command that sends only failed findings to Security Hub in region `us-gov-west-1`:

```
./prowler -r us-gov-west-1 -f us-gov-west-1 -S -M csv,json-asff -q
```

### Security Hub in China regions

To use Prowler and Security Hub integration in China regions there is an additional requirement, usage of `-r` is needed to point the API queries to the right API endpoint. Here is a sample command that sends only failed findings to Security Hub in region `cn-north-1`:

```
./prowler -r cn-north-1 -f cn-north-1 -q -S -M csv,json-asff
```

## CodeBuild deployment

Either to run Prowler once or based on a schedule this template makes it pretty straight forward. This template will create a CodeBuild environment and run Prowler directly leaving all reports in a bucket and creating a report also inside CodeBuild basedon the JUnit output from Prowler. Scheduling can be cron based like `cron(0 22 * * ? *)` or rate based like `rate(5 hours)` since CloudWatch Event rules (or Eventbridge) is used here.

The Cloud Formation template that helps you to do that is [here](https://github.com/prowler-cloud/prowler/blob/master/util/codebuild/codebuild-prowler-audit-account-cfn.yaml).

> This is a simple solution to monitor one account. For multiples accounts see [Multi Account and Continuous Monitoring](util/org-multi-account/README.md).

## Allowlist or remove a fail from resources

Sometimes you may find resources that are intentionally configured in a certain way that may be a bad practice but it is all right with it, for example an S3 bucket open to the internet hosting a web site, or a security group with an open port needed in your use case. Now you can use `-w allowlist_sample.txt` and add your resources as `checkID:resourcename` as in this command:

```
./prowler -w allowlist_sample.txt
```

S3 URIs are also supported as allowlist file, e.g. `s3://bucket/prefix/allowlist_sample.txt`

> Make sure that the used credentials have s3:GetObject permissions in the S3 path where the allowlist file is located.

DynamoDB table ARNs are also supported as allowlist file, e.g. `arn:aws:dynamodb:us-east-1:111111222222:table/allowlist`

> Make sure that the table has `account_id` as partition key and `rule` as sort key, and that the used credentials have `dynamodb:PartiQLSelect` permissions in the table.
>
> <p align="left"><img src="https://user-images.githubusercontent.com/38561120/165769502-296f9075-7cc8-445e-8158-4b21804bfe7e.png" alt="image" width="397" height="252" /></p>

> The field `account_id` can contain either an account ID or an `*` (which applies to all the accounts that use this table as a whitelist). As in the traditional allowlist file, the `rule` field must contain `checkID:resourcename` pattern.
>
> <p><img src="https://user-images.githubusercontent.com/38561120/165770610-ed5c2764-7538-44c2-9195-bcfdecc4ef9b.png" alt="image" width="394" /></p>

Allowlist option works along with other options and adds a `WARNING` instead of `INFO`, `PASS` or `FAIL` to any output format except for `json-asff`.

## Inventory

With Prowler you can get an inventory of your AWS resources. To do so, run `./prowler -i` to see what AWS resources you have deployed in your AWS account. This feature lists almost all resources in all regions based on [this](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html) API call. Note that it does not cover 100% of resource types.

The inventory will be stored in an output `csv` file by default, under common Prowler `output` folder, with the following format: `prowler-inventory-${ACCOUNT_NUM}-${OUTPUT_DATE}.csv`

## How to fix every FAIL

Check your report and fix the issues following all specific guidelines per check in <https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf>

## Troubleshooting

### STS expired token

If you are using an STS token for AWS-CLI and your session is expired you probably get this error:

```sh
A client error (ExpiredToken) occurred when calling the GenerateCredentialReport operation: The security token included in the request is expired
```

To fix it, please renew your token by authenticating again to the AWS API, see next section below if you use MFA.

### Run Prowler with MFA protected credentials

To run Prowler using a profile that requires MFA you just need to get the session token before hand. Just make sure you use this command:

```sh
aws --profile <YOUR_AWS_PROFILE> sts get-session-token --duration 129600 --serial-number <ARN_OF_MFA> --token-code <MFA_TOKEN_CODE> --output text
```

Once you get your token you can export it as environment variable:

```sh
export AWS_PROFILE=YOUR_AWS_PROFILE
export AWS_SESSION_TOKEN=YOUR_NEW_TOKEN
AWS_SECRET_ACCESS_KEY=YOUR_SECRET
export AWS_ACCESS_KEY_ID=YOUR_KEY
```

or set manually up your `~/.aws/credentials` file properly.

There are some helpfull tools to save time in this process like [aws-mfa-script](https://github.com/asagage/aws-mfa-script) or [aws-cli-mfa](https://github.com/sweharris/aws-cli-mfa).

### AWS Managed IAM Policies

[ViewOnlyAccess](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html#jf_view-only-user)

- Use case: This user can view a list of AWS resources and basic metadata in the account across all services. The user cannot read resource content or metadata that goes beyond the quota and list information for resources.
- Policy description: This policy grants List*, Describe*, Get*, View*, and Lookup\* access to resources for most AWS services. To see what actions this policy includes for each service, see [ViewOnlyAccess Permissions](https://console.aws.amazon.com/iam/home#policies/arn:aws:iam::aws:policy/job-function/ViewOnlyAccess)

[SecurityAudit](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html#jf_security-auditor)

- Use case: This user monitors accounts for compliance with security requirements. This user can access logs and events to investigate potential security breaches or potential malicious activity.
- Policy description: This policy grants permissions to view configuration data for many AWS services and to review their logs. To see what actions this policy includes for each service, see [SecurityAudit Permissions](https://console.aws.amazon.com/iam/home#policies/arn:aws:iam::aws:policy/SecurityAudit)

### Custom IAM Policy

[Prowler-Additions-Policy](iam/prowler-additions-policy.json)

Some new and specific checks require Prowler to inherit more permissions than SecurityAudit and ViewOnlyAccess to work properly. In addition to the AWS managed policies, "SecurityAudit" and "ViewOnlyAccess", the user/role you use for checks may need to be granted a custom policy with a few more read-only permissions (to support additional services mostly). Here is an example policy with the additional rights, "Prowler-Additions-Policy" (see below bootstrap script for set it up):

- [iam/prowler-additions-policy.json](iam/prowler-additions-policy.json)

[Prowler-Security-Hub Policy](iam/prowler-security-hub.json)

Allows Prowler to import its findings to [AWS Security Hub](https://aws.amazon.com/security-hub). More information in [Security Hub integration](#security-hub-integration):

- [iam/prowler-security-hub.json](iam/prowler-security-hub.json)

### Bootstrap Script

Quick bash script to set up a "prowler" IAM user with "SecurityAudit" and "ViewOnlyAccess" group with the required permissions (including "Prowler-Additions-Policy"). To run the script below, you need a user with administrative permissions; set the `AWS_DEFAULT_PROFILE` to use that account:

```sh
export AWS_DEFAULT_PROFILE=default
export ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' | tr -d '"')
aws iam create-group --group-name Prowler
aws iam create-policy --policy-name Prowler-Additions-Policy --policy-document file://$(pwd)/iam/prowler-additions-policy.json
aws iam attach-group-policy --group-name Prowler --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-group-policy --group-name Prowler --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
aws iam attach-group-policy --group-name Prowler --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/Prowler-Additions-Policy
aws iam create-user --user-name prowler
aws iam add-user-to-group --user-name prowler --group-name Prowler
aws iam create-access-key --user-name prowler
unset ACCOUNT_ID AWS_DEFAULT_PROFILE
```

The `aws iam create-access-key` command will output the secret access key and the key id; keep these somewhere safe, and add them to `~/.aws/credentials` with an appropriate profile name to use them with Prowler. This is the only time the secret key will be shown. If you lose it, you will need to generate a replacement.

> [This CloudFormation template](iam/create_role_to_assume_cfn.yaml) may also help you on that task.

## Extras

We are adding additional checks to improve the information gather from each account, these checks are out of the scope of the CIS benchmark for AWS, but we consider them very helpful to get to know each AWS account set up and find issues on it.

Some of these checks look for publicly facing resources may not actually be fully public due to other layered controls like S3 Bucket Policies, Security Groups or Network ACLs.

To list all existing checks in the extras group run the command below:

```sh
./prowler -l -g extras
```

> There are some checks not included in that list, they are experimental or checks that take long to run like `extra759` and `extra760` (search for secrets in Lambda function variables and code).

To check all extras in one command:

```sh
./prowler -g extras
```

or to run just one of the checks:

```sh
./prowler -c extraNUMBER
```

or to run multiple extras in one go:

```sh
./prowler -c extraNumber,extraNumber
```

## Forensics Ready Checks

With this group of checks, Prowler looks if each service with logging or audit capabilities has them enabled to ensure all needed evidences are recorded and collected for an eventual digital forensic investigation in case of incident. List of checks part of this group (you can also see all groups with `./prowler -L`). The list of checks can be seen in the group file at:

[groups/group8_forensics](groups/group8_forensics)

The `forensics-ready` group of checks uses existing and extra checks. To get a forensics readiness report, run this command:

```sh
./prowler -g forensics-ready
```

## GDPR Checks

With this group of checks, Prowler shows result of checks related to GDPR, more information [here](https://github.com/prowler-cloud/prowler/issues/189). The list of checks can be seen in the group file at:

[groups/group9_gdpr](groups/group9_gdpr)

The `gdpr` group of checks uses existing and extra checks. To get a GDPR report, run this command:

```sh
./prowler -g gdpr
```

## AWS FTR Checks

With this group of checks, Prowler shows result of checks related to the AWS Foundational Technical Review, more information [here](https://apn-checklists.s3.amazonaws.com/foundational/partner-hosted/partner-hosted/CVLHEC5X7.html). The list of checks can be seen in the group file at:

[groups/group25_ftr](groups/group25_FTR)

The `ftr` group of checks uses existing and extra checks. To get a AWS FTR report, run this command:

```sh
./prowler -g ftr
```

## HIPAA Checks

With this group of checks, Prowler shows results of controls related to the "Security Rule" of the Health Insurance Portability and Accountability Act aka [HIPAA](https://www.hhs.gov/hipaa/for-professionals/security/index.html) as defined in [45 CFR Subpart C - Security Standards for the Protection of Electronic Protected Health Information](https://www.law.cornell.edu/cfr/text/45/part-164/subpart-C) within [PART 160 - GENERAL ADMINISTRATIVE REQUIREMENTS](https://www.law.cornell.edu/cfr/text/45/part-160) and [Subpart A](https://www.law.cornell.edu/cfr/text/45/part-164/subpart-A) and [Subpart C](https://www.law.cornell.edu/cfr/text/45/part-164/subpart-C) of PART 164 - SECURITY AND PRIVACY

More information on the original PR is [here](https://github.com/prowler-cloud/prowler/issues/227).

### Note on Business Associate Addendum's (BAA)

Under the HIPAA regulations, cloud service providers (CSPs) such as AWS are considered business associates. The Business Associate Addendum (BAA) is an AWS contract that is required under HIPAA rules to ensure that AWS appropriately safeguards protected health information (PHI). The BAA also serves to clarify and limit, as appropriate, the permissible uses and disclosures of PHI by AWS, based on the relationship between AWS and our customers, and the activities or services being performed by AWS. Customers may use any AWS service in an account designated as a HIPAA account, but they should only process, store, and transmit protected health information (PHI) in the HIPAA-eligible services defined in the Business Associate Addendum (BAA). For the latest list of HIPAA-eligible AWS services, see [HIPAA Eligible Services Reference](https://aws.amazon.com/compliance/hipaa-eligible-services-reference/).

More information on AWS & HIPAA can be found [here](https://aws.amazon.com/compliance/hipaa-compliance/)

The list of checks showed by this group is as follows, they will be mostly relevant for Subsections [164.306 Security standards: General rules](https://www.law.cornell.edu/cfr/text/45/164.306) and [164.312 Technical safeguards](https://www.law.cornell.edu/cfr/text/45/164.312). Prowler is only able to make checks in the spirit of the technical requirements outlined in these Subsections, and cannot cover all procedural controls required. They be found in the group file at:

[groups/group10_hipaa](groups/group10_hipaa)

The `hipaa` group of checks uses existing and extra checks. To get a HIPAA report, run this command:

```sh
./prowler -g hipaa
```

## Trust Boundaries Checks

### Definition and Terms

The term "trust boundary" is originating from the threat modelling process and the most popular contributor Adam Shostack and author of "Threat Modeling: Designing for Security" defines it as following ([reference](https://adam.shostack.org/uncover.html)):

> Trust boundaries are perhaps the most subjective of all: these represent the border between trusted and untrusted elements. Trust is complex. You might trust your mechanic with your car, your dentist with your teeth, and your banker with your money, but you probably don't trust your dentist to change your spark plugs.

AWS is made to be flexible for service links within and between different AWS accounts, we all know that.

This group of checks helps to analyse a particular AWS account (subject) on existing links to other AWS accounts across various AWS services, in order to identify untrusted links.

### Run

To give it a quick shot just call:

```sh
./prowler -g trustboundaries
```

### Scenarios

Currently, this check group supports two different scenarios:

1. Single account environment: no action required, the configuration is happening automatically for you.
2. Multi account environment: in case you environment has multiple trusted and known AWS accounts you maybe want to append them manually to [groups/group16_trustboundaries](groups/group16_trustboundaries) as a space separated list into `GROUP_TRUSTBOUNDARIES_TRUSTED_ACCOUNT_IDS` variable, then just run prowler.

### Coverage

Current coverage of Amazon Web Service (AWS) taken from [here](https://docs.aws.amazon.com/whitepapers/latest/aws-overview/introduction.html):
| Topic | Service | Trust Boundary |
|---------------------------------|------------|---------------------------------------------------------------------------|
| Networking and Content Delivery | Amazon VPC | VPC endpoints connections ([extra786](checks/check_extra786)) |
| | | VPC endpoints allowlisted principals ([extra787](checks/check_extra787)) |

All ideas or recommendations to extend this group are very welcome [here](https://github.com/prowler-cloud/prowler/issues/new/choose).

### Detailed Explanation of the Concept

The diagrams depict two common scenarios, single account and multi account environments.
Every circle represents one AWS account.
The dashed line represents the trust boundary, that separates trust and untrusted AWS accounts.
The arrow simply describes the direction of the trust, however the data can potentially flow in both directions.

Single Account environment assumes that only the AWS account subject to this analysis is trusted. However, there is a chance that two VPCs are existing within that one AWS account which are still trusted as a self reference.
![single-account-environment](/docs/images/prowler-single-account-environment.png)

Multi Account environments assumes a minimum of two trusted or known accounts. For this particular example all trusted and known accounts will be tested. Therefore `GROUP_TRUSTBOUNDARIES_TRUSTED_ACCOUNT_IDS` variable in [groups/group16_trustboundaries](groups/group16_trustboundaries) should include all trusted accounts Account #A, Account #B, Account #C, and Account #D in order to finally raise Account #E and Account #F for being untrusted or unknown.
![multi-account-environment](/docs/images/prowler-multi-account-environment.png)

## Custom Checks

Using `./prowler -c extra9999 -a` you can build your own on-the-fly custom check by specifying the AWS CLI command to execute.

> Omit the "aws" command and only use its parameters within quotes and do not nest quotes in the aws parameter, --output text is already included in the check.
>
> Here is an example of a check to find SGs with inbound port 80:

```sh
./prowler -c extra9999 -a 'ec2 describe-security-groups --filters Name=ip-permission.to-port,Values=80 --query SecurityGroups[*].GroupId[]]'
```

In order to add any new check feel free to create a new extra check in the extras group or other group. To do so, you will need to follow these steps:

1. Follow structure in file `checks/check_sample`
2. Name your check with a number part of an existing group or a new one
3. Save changes and run it as `./prowler -c extraNN`
4. Send me a pull request! :)

## Add Custom Groups

1. Follow structure in file `groups/groupN_sample`
1. Name your group with a non existing number
1. Save changes and run it as `./prowler -g extraNN`
1. Send me a pull request! :)

- You can also create a group with only the checks that you want to perform in your company, for instance a group named `group9_mycompany` with only the list of checks that you care or your particular compliance applies.

## Third Party Integrations

### Telegram

Javier Pecete has done an awesome job integrating Prowler with Telegram, you have more details here <https://github.com/i4specete/ServerTelegramBot>

### Cloud Security Suite

The guys of SecurityFTW have added Prowler in their Cloud Security Suite along with other cool security tools <https://github.com/SecurityFTW/cs-suite>

## License

Prowler is licensed as Apache License 2.0 as specified in each file. You may obtain a copy of the License at
<http://www.apache.org/licenses/LICENSE-2.0>

**I'm not related anyhow with CIS organization, I just write and maintain Prowler to help companies over the world to make their cloud infrastructure more secure.**

If you want to contact me visit <https://blyx.com/contact> or follow me on Twitter <https://twitter.com/prowler-cloud> my DMs are open.
