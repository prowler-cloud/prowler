# Prowler: AWS CIS Benchmark Tool

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Requirements and Installation](#requirements-and-installation)
- [Usage](#usage)
- [Fix](#fix)
- [Screenshots](#screenshots)
- [Troubleshooting](#troubleshooting)
- [Extras](#extras)
- [Forensics Ready Checks](#forensics-ready-checks)
- [GDPR Checks](#gdpr-checks)
- [HIPAA Checks](#hipaa-checks)
- [Add Custom Checks](#add-custom-checks)
- [Third Party Integrations](#third-party-integrations)
- [Full list of checks and groups](/LIST_OF_CHECKS_AND_GROUPS.md)
- [License](#license)

## Description

Prowler is a command line tool for AWS Security Best Practices Assessment, Auditing, Hardening and Forensics Readiness Tool.

It follows guidelines of the CIS Amazon Web Services Foundations Benchmark (49 checks) and has 40 additional checks including related to GDPR and HIPAA.

Read more about [CIS Amazon Web Services Foundations Benchmark v1.2.0 - 05-23-2018](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf)

## Features

It covers hardening and security best practices for all AWS regions related to the next groups:

- Identity and Access Management (22 checks) [group1]
- Logging (9 checks) [group2]
- Monitoring (14 checks) [group3]
- Networking (4 checks) [group4]
- CIS Level 1 [cislevel1]
- CIS Level 2 [cislevel2]
- Extras (39 checks) *see Extras section* [extras]
- Forensics related group of checks [forensics-ready]
- GDPR [gdpr] Read more [here](#gdpr-checks)
- HIPAA [hipaa] Read more [here](#hipaa-checks)


For a comprehensive list and resolution look at the guide on the link above.

With Prowler you can:

- get a colorful or monochrome report
- a CSV format report for diff
- run specific checks without having to run the entire report
- check multiple AWS accounts in parallel

## Requirements and Installation

This script has been written in bash using AWS-CLI and it works in Linux and OSX.

- Make sure the latest version of AWS-CLI is installed on your workstation, and other components needed, with Python pip already installed:

    ```sh
    pip install awscli ansi2html detect-secrets
    ```

    AWS-CLI can be also installed it using "brew", "apt", "yum" or manually from <https://aws.amazon.com/cli/>, but `ansi2html` and `detect-secrets` has to be installed using `pip`. You will need to install `jq` to get more accuracy in some checks. 

- Previous steps, from your workstation:

    ```sh
    git clone https://github.com/toniblyx/prowler
    cd prowler
    ```

- Make sure you have properly configured your AWS-CLI with a valid Access Key and Region or declare AWS variables properly:

    ```sh
    aws configure
    ```
    or 
    ```sh
    export AWS_ACCESS_KEY_ID="ASXXXXXXX"
    export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
    export AWS_SESSION_TOKEN="XXXXXXXXX"
    ```

- Those credentials must be associated to a user or role with proper permissions to do all checks. To make sure add SecurityAuditor default policy to your user. Policy ARN is

    ```sh
    arn:aws:iam::aws:policy/SecurityAudit
    ```

    > In some cases you may need more list or get permissions in some services, look at the Troubleshooting section for a more comprehensive policy if you find issues with the default SecurityAudit policy.

## Usage

1. Run the `prowler` command without options (it will use your environment variable credentials if they exist or will default to using the `~/.aws/credentials` file and run checks over all regions when needed. The default region is us-east-1):

    ```sh
    ./prowler
    ```

    Use `-l` to list all available checks and group of checks (sections)

    If you want to avoid installing dependences run it using Docker:
    
    ```sh
    docker run -ti --rm --name prowler --env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY --env AWS_SESSION_TOKEN toniblyx/prowler:latest
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

1. If you want to save your report for later analysis:

    ```sh
    ./prowler -M mono > prowler-report.txt
    ```

    or if you want a coloured HTML report do:

    ```sh
    pip install ansi2html
    ./prowler | ansi2html -la > report.html
    ```

    or if you want a pipe-delimited report file, do:

    ```sh
    ./prowler -M csv > output.psv
    ```
    or json formatted output using jq, do:

    ```sh
    ./prowler -M json > prowler-output.json
    ```

    or save your report in a S3 bucket:

    ```sh
    ./prowler -M mono | aws s3 cp - s3://bucket-name/prowler-report.txt
    ```

1. To perform an assessment based on CIS Profile Definitions you can use cislevel1 or cislevel2 with `-g` flag, more information about this [here, page 8](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf):

    ```sh
    ./prowler -g cislevel1
    ```

1. If you want to run Prowler to check multiple AWS accounts in parallel (runs up to 4 simultaneously `-P 4`):

    ```sh
    grep -E '^\[([0-9A-Aa-z_-]+)\]'  ~/.aws/credentials | tr -d '][' | shuf |  \
    xargs -n 1 -L 1 -I @ -r -P 4 ./prowler -p @ -M csv  2> /dev/null  >> all-accounts.csv
    ```

1. For help use:

    ```
    ./prowler -h

    USAGE:
        prowler [ -p <profile> -r <region>  -h ]

    Options:
        -p <profile>        specify your AWS profile to use (i.e.: default)
        -r <region>         specify an AWS region to direct API requests to
                                (i.e.: us-east-1), all regions are checked anyway if the check requires it
        -c <check_id>       specify a check id, to see all available checks use -l option
                                (i.e.: check11 for check 1.1 or extra71 for extra check 71)
        -g <group_id>       specify a group of checks by id, to see all available group of checks use -L
                                (i.e.: check3 for entire section 3, cislevel1 for CIS Level 1 Profile Definitions or forensics-ready)
        -f <filterregion>   specify an AWS region to run checks against
                                (i.e.: us-west-1)
        -m <maxitems>       specify the maximum number of items to return for long-running requests (default: 100)
        -M <mode>           output mode: text (default), mono, json, csv (separator is ,; data is on stdout; progress on stderr)
        -k                  keep the credential report
        -n                  show check numbers to sort easier
                                (i.e.: 1.01 instead of 1.1)
        -l                  list all available checks only (does not perform any check)
        -L                  list all groups (does not perform any check)
        -e                  exclude group extras
        -E                  execute all tests except a list of specified checks separated by comma (i.e. check21,check31)
        -b                  do not print Prowler banner
        -V                  show version number & exit
        -s                  show scoring report
        -h                  this help
    ```

## How to fix every FAIL

Check your report and fix the issues following all specific guidelines per check in <https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf>

## Screenshots

- Sample screenshot of report first lines:

    <img width="1125" alt="screenshot 2016-09-13 16 05 42" src="https://cloud.githubusercontent.com/assets/3985464/18489640/50fe6824-79cc-11e6-8a9c-e788b88a8a6b.png">

- Sample screenshot of single check for check 3.3:

    <img width="1006" alt="screenshot 2016-09-14 13 20 46" src="https://cloud.githubusercontent.com/assets/3985464/18522590/a04ca9a6-7a7e-11e6-8730-b545c9204990.png">

## Troubleshooting

### STS expired token

If you are using an STS token for AWS-CLI and your session is expired you probably get this error:

```
A client error (ExpiredToken) occurred when calling the GenerateCredentialReport operation: The security token included in the request is expired
```

To fix it, please renew your token by authenticating again to the AWS API, see next section below if you use MFA.

### Run Prowler with MFA protected credentials

To run Prowler using a profile that requires MFA you just need to get the session token before hand. Just make sure you use this command:

```
aws --profile <YOUR_AWS_PROFILE> sts get-session-token --duration 129600 --serial-number <ARN_OF_MFA> --token-code <MFA_TOKEN_CODE> --output text
 ```
Once you get your token you can export it as environment variable:
```
export AWS_PROFILE=YOUR_AWS_PROFILE
export AWS_SESSION_TOKEN=YOUR_NEW_TOKEN
AWS_SECRET_ACCESS_KEY=YOUR_SECRET
export AWS_ACCESS_KEY_ID=YOUR_KEY
```
or set manually up your `~/.aws/credentials` file properly.

There are some helpfull tools to save time in this process like [aws-mfa-script](https://github.com/asagage/aws-mfa-script) or [aws-cli-mfa](https://github.com/sweharris/aws-cli-mfa).

### Custom IAM Policy

Some new and specific checks require Prowler to inherit more permissions than SecurityAudit to work properly. In addition to the AWS managed policy "SecurityAudit" for the role you use for checks you may need to create a custom policy with a few more permissions (get and list and additional services mostly). Here you go a good example for a "ProwlerReadOnlyPolicy" (see below bootstrap script for set it up):

[iam/prowler-additions-policy.json](iam/prowler-additions-policy.json)

> Note: Action `ec2:get*` is included in "ProwlerReadOnlyPolicy" policy above, that includes `get-password-data`, type `aws ec2 get-password-data help` to better understand its implications. 

### Bootstrap Script

Quick bash script to set up a "prowler" IAM user with "SecurityAudit" group with the required permissions (including "ProwlerReadOnlyPolicy"). To run the script below, you need user with administrative permissions; set the `AWS_DEFAULT_PROFILE` to use that account:

```sh
export AWS_DEFAULT_PROFILE=default
export ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' | tr -d '"')
aws iam create-group --group-name SecurityAudit
aws iam create-policy --policy-name ProwlerReadOnlyPolicy --policy-document file://$(pwd)/iam/prowler-additions-policy.json
aws iam attach-group-policy --group-name SecurityAudit --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-group-policy --group-name SecurityAudit --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/ProwlerReadOnlyPolicy
aws iam create-user --user-name prowler
aws iam add-user-to-group --user-name prowler --group-name SecurityAudit
aws iam create-access-key --user-name prowler
unset ACCOUNT_ID AWS_DEFAULT_PROFILE
```

The `aws iam create-access-key` command will output the secret access key and the key id; keep these somewhere safe, and add them to `~/.aws/credentials` with an appropriate profile name to use them with prowler. This is the only time they secret key will be shown.  If you lose it, you will need to generate a replacement.

## Extras

We are adding additional checks to improve the information gather from each account, these checks are out of the scope of the CIS benchmark for AWS but we consider them very helpful to get to know each AWS account set up and find issues on it.

Some of these checks look for publicly facing resources may not actually be fully public due to other layered controls like S3 Bucket Policies, Security Groups or Network ACLs.

To list all existing checks please run the command below:

```
./prowler -l
```

>There are some checks not included in that list, they are experimental or checks that takes long to run like `extra759` and `extra760` (search for secrets in Lambda function variables and code).

To check all extras in one command:

```sh
./prowler -g extras
```

or to run just one of the checks:

```sh
./prowler -c extraNUMBER
```

## Forensics Ready Checks

With this group of checks, Prowler looks if each service with logging or audit capabilities has them enabled to ensure all needed evidences are recorded and collected for an eventual digital forensic investigation in case of incident. List of checks part of this group (you can also see all groups with `./prowler -L`). The list of checks can be seen in the group file at:

[groups/group8_forensics](groups/group8_forensics)

The `forensics-ready` group of checks uses existing and extra checks. To get a forensics readiness report, run this command:

```sh
./prowler -g forensics-ready
```

## GDPR Checks

With this group of checks, Prowler shows result of checks related to GDPR, more information [here](https://github.com/toniblyx/prowler/issues/189). The list of checks can be seen in the group file at:

[groups/group9_gdpr](groups/group9_gdpr)

The `gdpr` group of checks uses existing and extra checks. To get a GDPR report, run this command:

```sh
./prowler -g gdpr
```

## HIPAA Checks

With this group of checks, Prowler shows results of controls related to the "Security Rule" of the Health Insurance Portability and Accountability Act aka [HIPAA](https://www.hhs.gov/hipaa/for-professionals/security/index.html) as defined in [45 CFR Subpart C - Security Standards for the Protection of Electronic Protected Health Information](https://www.law.cornell.edu/cfr/text/45/part-164/subpart-C) within [PART 160 - GENERAL ADMINISTRATIVE REQUIREMENTS](https://www.law.cornell.edu/cfr/text/45/part-160) and [Subpart A](https://www.law.cornell.edu/cfr/text/45/part-164/subpart-A) and [Subpart C](https://www.law.cornell.edu/cfr/text/45/part-164/subpart-C) of PART 164 - SECURITY AND PRIVACY

More information on the original PR is [here](https://github.com/toniblyx/prowler/issues/227).

### Note on Business Associate Addendum's (BAA)
Under the HIPAA regulations, cloud service providers (CSPs) such as AWS are considered business associates. The Business Associate Addendum (BAA) is an AWS contract that is required under HIPAA rules to ensure that AWS appropriately safeguards protected health information (PHI). The BAA also serves to clarify and limit, as appropriate, the permissible uses and disclosures of PHI by AWS, based on the relationship between AWS and our customers, and the activities or services being performed by AWS. Customers may use any AWS service in an account designated as a HIPAA account, but they should only process, store, and transmit protected health information (PHI) in the HIPAA-eligible services defined in the Business Associate Addendum (BAA). For the latest list of HIPAA-eligible AWS services, see [HIPAA Eligible Services Reference](https://aws.amazon.com/compliance/hipaa-eligible-services-reference/).

More information on AWS & HIPAA can be found [here](https://aws.amazon.com/compliance/hipaa-compliance/)

The list of checks showed by this group is as follows, they will be mostly relevant for Subsections [164.306 Security standards: General rules](https://www.law.cornell.edu/cfr/text/45/164.306) and [164.312 Technical safeguards](https://www.law.cornell.edu/cfr/text/45/164.312). Prowler is only able to make checks in the spirit of the technical requirements outlined in these Subsections, and cannot cover all procedural controls required. They be found in the group file at:

[groups/group10_hipaa](groups/group10_hipaa)

The `hipaa` group of checks uses existing and extra checks. To get a HIPAA report, run this command:

```sh
./prowler -g hipaa
```

## Add Custom Checks

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

All CIS based checks in the checks folder are licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International Public License.
The link to the license terms can be found at
<https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode>
Any other piece of code is licensed as Apache License 2.0 as specified in each file. You may obtain a copy of the License at
<http://www.apache.org/licenses/LICENSE-2.0>

NOTE: If you are interested in using Prowler for commercial purposes remember that due to the CC4.0 license “The distributors or partners that are interested and using Prowler would need to enroll as CIS SecureSuite Members to incorporate this product, which includes references to CIS resources, in their offering.". Information about CIS pricing for vendors here: <https://www.cisecurity.org/cis-securesuite/pricing-and-categories/product-vendor/>

**I'm not related anyhow with CIS organization, I just write and maintain Prowler to help companies over the world to make their cloud infrastructure more secure.**

If you want to contact me visit <https://blyx.com/contact>
