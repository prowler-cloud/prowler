```
_
_ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_|v2.0-beta2
|_| the handy cloud security tool

Date: Thu Apr 19 09:50:17 EDT 2018

Colors code for results:  INFO (Information), PASS (Recommended value),  FAIL (Fix required)

1.0 Identity and Access Management - [group1] **********************

1.1  [check11] Avoid the use of the root account (Scored)

1.2  [check12] Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)

1.3  [check13] Ensure credentials unused for 90 days or greater are disabled (Scored)

1.4  [check14] Ensure access keys are rotated every 90 days or less (Scored)

1.5  [check15] Ensure IAM password policy requires at least one uppercase letter (Scored)

1.6  [check16] Ensure IAM password policy require at least one lowercase letter (Scored)

1.7  [check17] Ensure IAM password policy require at least one symbol (Scored)

1.8  [check18] Ensure IAM password policy require at least one number (Scored)

1.9  [check19] Ensure IAM password policy requires minimum length of 14 or greater (Scored)

1.10  [check110] Ensure IAM password policy prevents password reuse: 24 or greater (Scored)

1.11  [check111] Ensure IAM password policy expires passwords within 90 days or less (Scored)

1.12  [check112] Ensure no root account access key exists (Scored)

1.13  [check113] Ensure MFA is enabled for the root account (Scored)

1.14  [check114] Ensure hardware MFA is enabled for the root account (Scored)

1.15  [check115] Ensure security questions are registered in the AWS account (Not Scored)

1.16  [check116] Ensure IAM policies are attached only to groups or roles (Scored)

1.17  [check117] Enable detailed billing (Scored)

1.18  [check118] Ensure IAM Master and IAM Manager roles are active (Scored)

1.19  [check119] Maintain current contact details (Scored)

1.20  [check120] Ensure security contact information is registered (Scored)

1.21 [check121] Ensure IAM instance roles are used for AWS resource access from instances (Not Scored)

1.22  [check122] Ensure a support role has been created to manage incidents with AWS Support (Scored)

1.23 [check123] Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)

1.24  [check124] Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)

2.0 Logging - [group2] *********************************************

2.1  [check21] Ensure CloudTrail is enabled in all regions (Scored)

2.2  [check22] Ensure CloudTrail log file validation is enabled (Scored)

2.3  [check23] Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  [check24] Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  [check25] Ensure AWS Config is enabled in all regions (Scored)

2.6  [check26] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

2.7  [check27] Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)

2.8  [check28] Ensure rotation for customer created CMKs is enabled (Scored)

3.0 Monitoring - [group3] ******************************************

3.1  [check31] Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)

3.2  [check32] Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)

3.3  [check33] Ensure a log metric filter and alarm exist for usage of root account (Scored)

3.4  [check34] Ensure a log metric filter and alarm exist for IAM policy changes (Scored)

3.5  [check35] Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)

3.6  [check36] Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)

3.7  [check37] Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)

3.8  [check38] Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)

3.9  [check39] Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)

3.10  [check310] Ensure a log metric filter and alarm exist for security group changes (Scored)

3.11  [check311] Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)

3.12  [check312] Ensure a log metric filter and alarm exist for changes to network gateways (Scored)

3.13  [check313] Ensure a log metric filter and alarm exist for route table changes (Scored)

3.14  [check314] Ensure a log metric filter and alarm exist for VPC changes (Scored)

3.15  [check315] Ensure appropriate subscribers to each SNS topic (Not Scored)

4.0 Networking - [group4] ******************************************

4.1  [check41] Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)

4.2  [check42] Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)

4.3  [check43] Ensure VPC Flow Logging is Enabled in all VPCs (Scored)

4.4  [check44] Ensure the default security group of every VPC restricts all traffic (Scored)

4.5 [check45] Ensure routing tables for VPC peering are "least access" (Not Scored)

5.0 CIS Level 1 - [cislevel1] **************************************

1.1  [check11] Avoid the use of the root account (Scored)

1.2  [check12] Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)

1.3  [check13] Ensure credentials unused for 90 days or greater are disabled (Scored)

1.4  [check14] Ensure access keys are rotated every 90 days or less (Scored)

1.5  [check15] Ensure IAM password policy requires at least one uppercase letter (Scored)

1.6  [check16] Ensure IAM password policy require at least one lowercase letter (Scored)

1.7  [check17] Ensure IAM password policy require at least one symbol (Scored)

1.8  [check18] Ensure IAM password policy require at least one number (Scored)

1.9  [check19] Ensure IAM password policy requires minimum length of 14 or greater (Scored)

1.10  [check110] Ensure IAM password policy prevents password reuse: 24 or greater (Scored)

1.11  [check111] Ensure IAM password policy expires passwords within 90 days or less (Scored)

1.12  [check112] Ensure no root account access key exists (Scored)

1.13  [check113] Ensure MFA is enabled for the root account (Scored)

1.15  [check115] Ensure security questions are registered in the AWS account (Not Scored)

1.16  [check116] Ensure IAM policies are attached only to groups or roles (Scored)

1.17  [check117] Enable detailed billing (Scored)

1.18  [check118] Ensure IAM Master and IAM Manager roles are active (Scored)

1.19  [check119] Maintain current contact details (Scored)

1.20  [check120] Ensure security contact information is registered (Scored)

1.22  [check122] Ensure a support role has been created to manage incidents with AWS Support (Scored)

1.23 [check123] Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)

1.24  [check124] Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)

2.1  [check21] Ensure CloudTrail is enabled in all regions (Scored)

2.3  [check23] Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  [check24] Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  [check25] Ensure AWS Config is enabled in all regions (Scored)

2.6  [check26] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

3.1  [check31] Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)

3.2  [check32] Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)

3.3  [check33] Ensure a log metric filter and alarm exist for usage of root account (Scored)

3.4  [check34] Ensure a log metric filter and alarm exist for IAM policy changes (Scored)

3.5  [check35] Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)

3.8  [check38] Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)

3.12  [check312] Ensure a log metric filter and alarm exist for changes to network gateways (Scored)

3.13  [check313] Ensure a log metric filter and alarm exist for route table changes (Scored)

3.14  [check314] Ensure a log metric filter and alarm exist for VPC changes (Scored)

3.15  [check315] Ensure appropriate subscribers to each SNS topic (Not Scored)

4.1  [check41] Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)

4.2  [check42] Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)

6.0 CIS Level 2 - [cislevel2] **************************************

1.1  [check11] Avoid the use of the root account (Scored)

1.2  [check12] Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)

1.3  [check13] Ensure credentials unused for 90 days or greater are disabled (Scored)

1.4  [check14] Ensure access keys are rotated every 90 days or less (Scored)

1.5  [check15] Ensure IAM password policy requires at least one uppercase letter (Scored)

1.6  [check16] Ensure IAM password policy require at least one lowercase letter (Scored)

1.7  [check17] Ensure IAM password policy require at least one symbol (Scored)

1.8  [check18] Ensure IAM password policy require at least one number (Scored)

1.9  [check19] Ensure IAM password policy requires minimum length of 14 or greater (Scored)

1.10  [check110] Ensure IAM password policy prevents password reuse: 24 or greater (Scored)

1.11  [check111] Ensure IAM password policy expires passwords within 90 days or less (Scored)

1.12  [check112] Ensure no root account access key exists (Scored)

1.13  [check113] Ensure MFA is enabled for the root account (Scored)

1.14  [check114] Ensure hardware MFA is enabled for the root account (Scored)

1.15  [check115] Ensure security questions are registered in the AWS account (Not Scored)

1.16  [check116] Ensure IAM policies are attached only to groups or roles (Scored)

1.17  [check117] Enable detailed billing (Scored)

1.18  [check118] Ensure IAM Master and IAM Manager roles are active (Scored)

1.19  [check119] Maintain current contact details (Scored)

1.20  [check120] Ensure security contact information is registered (Scored)

1.21 [check121] Ensure IAM instance roles are used for AWS resource access from instances (Not Scored)

1.22  [check122] Ensure a support role has been created to manage incidents with AWS Support (Scored)

1.23 [check123] Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)

1.24  [check124] Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)

2.1  [check21] Ensure CloudTrail is enabled in all regions (Scored)

2.2  [check22] Ensure CloudTrail log file validation is enabled (Scored)

2.3  [check23] Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  [check24] Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  [check25] Ensure AWS Config is enabled in all regions (Scored)

2.6  [check26] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

2.7  [check27] Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)

2.8  [check28] Ensure rotation for customer created CMKs is enabled (Scored)

3.1  [check31] Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)

3.2  [check32] Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)

3.3  [check33] Ensure a log metric filter and alarm exist for usage of root account (Scored)

3.4  [check34] Ensure a log metric filter and alarm exist for IAM policy changes (Scored)

3.5  [check35] Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)

3.6  [check36] Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)

3.7  [check37] Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)

3.8  [check38] Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)

3.9  [check39] Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)

3.10  [check310] Ensure a log metric filter and alarm exist for security group changes (Scored)

3.11  [check311] Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)

3.12  [check312] Ensure a log metric filter and alarm exist for changes to network gateways (Scored)

3.13  [check313] Ensure a log metric filter and alarm exist for route table changes (Scored)

3.14  [check314] Ensure a log metric filter and alarm exist for VPC changes (Scored)

3.15  [check315] Ensure appropriate subscribers to each SNS topic (Not Scored)

4.1  [check41] Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)

4.2  [check42] Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)

4.3  [check43] Ensure VPC Flow Logging is Enabled in all VPCs (Scored)

4.4  [check44] Ensure the default security group of every VPC restricts all traffic (Scored)

4.5 [check45] Ensure routing tables for VPC peering are "least access" (Not Scored)

7.0 Extras - [extras] **********************************************

7.1 [extra71] Ensure users with AdministratorAccess policy have MFA tokens enabled (Not Scored) (Not part of CIS benchmark)

7.2 [extra72] Ensure there are no EBS Snapshots set as Public (Not Scored) (Not part of CIS benchmark)

7.3 [extra73] Ensure there are no S3 buckets open to the Everyone or Any AWS user (Not Scored) (Not part of CIS benchmark)

7.4 [extra74] Ensure there are no Security Groups without ingress filtering being used (Not Scored) (Not part of CIS benchmark)

7.5 [extra75] Ensure there are no Security Groups not being used (Not Scored) (Not part of CIS benchmark)

7.6 [extra75] Ensure there are no EC2 AMIs set as Public (Not Scored) (Not part of CIS benchmark)

7.7 [extra77] Ensure there are no ECR repositories set as Public (Not Scored) (Not part of CIS benchmark)

7.8 [extra78] Ensure there are no Public Accessible RDS instances (Not Scored) (Not part of CIS benchmark)

7.9 [extra79] Check for internet facing Elastic Load Balancers (Not Scored) (Not part of CIS benchmark)

7.10 [extra710] Check for internet facing EC2 Instances (Not Scored) (Not part of CIS benchmark)

7.11 [extra711] Check for Publicly Accessible Redshift Clusters (Not Scored) (Not part of CIS benchmark)

7.12 [extra712] Check if Amazon Macie is enabled (Not Scored) (Not part of CIS benchmark)

7.13 [extra713] Check if GuardDuty is enabled (Not Scored) (Not part of CIS benchmark)

7.14 [extra714] Check if CloudFront distributions have logging enabled (Not Scored) (Not part of CIS benchmark)

7.15 [extra715] Check if Elasticsearch Service domains have logging enabled (Not Scored) (Not part of CIS benchmark)

7.16 [extra716] Check if Elasticsearch Service domains allow open access (Not Scored) (Not part of CIS benchmark)

7.17 [extra717] Check if Elastic Load Balancers have logging enabled (Not Scored) (Not part of CIS benchmark)

7.18 [extra718] Check if S3 buckets have server access logging enabled (Not Scored) (Not part of CIS benchmark)

7.19 [extra719] Check if Route53 hosted zones are logging queries to CloudWatch Logs (Not Scored) (Not part of CIS benchmark)

7.20 [extra720] Check if Lambda functions invoke API operations are being recorded by CloudTrail (Not Scored) (Not part of CIS benchmark)

7.21 [extra721] Check if Redshift cluster has audit logging enabled (Not Scored) (Not part of CIS benchmark)

7.22 [extra722] Check if API Gateway has logging enabled (Not Scored) (Not part of CIS benchmark)

7.23 [extra723] Check if RDS Snapshots are public (Not Scored) (Not part of CIS benchmark)

7.24 [extra724] Check if ACM certificates have Certificate Transparency logging enabled (Not Scored) (Not part of CIS benchmark)

7.25 [extra725] Check if S3 buckets have Object-level logging enabled in CloudTrail (Not Scored) (Not part of CIS benchmark)

8.0 Forensics Readiness - [forensics-ready] ************************

2.1  [check21] Ensure CloudTrail is enabled in all regions (Scored)

2.2  [check22] Ensure CloudTrail log file validation is enabled (Scored)

2.3  [check23] Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  [check24] Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  [check25] Ensure AWS Config is enabled in all regions (Scored)

2.6  [check26] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

2.7  [check27] Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)

4.3  [check43] Ensure VPC Flow Logging is Enabled in all VPCs (Scored)

7.12 [extra712] Check if Amazon Macie is enabled (Not Scored) (Not part of CIS benchmark)

7.13 [extra713] Check if GuardDuty is enabled (Not Scored) (Not part of CIS benchmark)

7.14 [extra714] Check if CloudFront distributions have logging enabled (Not Scored) (Not part of CIS benchmark)

7.15 [extra715] Check if Elasticsearch Service domains have logging enabled (Not Scored) (Not part of CIS benchmark)

7.17 [extra717] Check if Elastic Load Balancers have logging enabled (Not Scored) (Not part of CIS benchmark)

7.18 [extra718] Check if S3 buckets have server access logging enabled (Not Scored) (Not part of CIS benchmark)

7.19 [extra719] Check if Route53 hosted zones are logging queries to CloudWatch Logs (Not Scored) (Not part of CIS benchmark)

7.20 [extra720] Check if Lambda functions invoke API operations are being recorded by CloudTrail (Not Scored) (Not part of CIS benchmark)

7.21 [extra721] Check if Redshift cluster has audit logging enabled (Not Scored) (Not part of CIS benchmark)

7.22 [extra722] Check if API Gateway has logging enabled (Not Scored) (Not part of CIS benchmark)

7.25 [extra725] Check if S3 buckets have Object-level logging enabled in CloudTrail (Not Scored) (Not part of CIS benchmark)

8.0 GDPR Readiness - [gdpr] ****************************************
[09:50]toni@pumba:~/Downloads/prowler$
[09:52]toni@pumba:~/Downloads/prowler$ git status
On branch devel
Your branch is up to date with 'origin/devel'.

Changes not staged for commit:
(use "git add <file>..." to update what will be committed)
(use "git checkout -- <file>..." to discard changes in working directory)

modified:   README.md

no changes added to commit (use "git add" and/or "git commit -a")
[09:52]toni@pumba:~/Downloads/prowler$ git add .
[09:52]toni@pumba:~/Downloads/prowler$ git commit -m "added -g option to README and fixes"
[devel 2362518] added -g option to README and fixes
1 file changed, 5 insertions(+), 3 deletions(-)
[09:52]toni@pumba:~/Downloads/prowler$ git push origin devel
Counting objects: 3, done.
Delta compression using up to 8 threads.
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 511 bytes | 511.00 KiB/s, done.
Total 3 (delta 2), reused 0 (delta 0)
remote: Resolving deltas: 100% (2/2), completed with 2 local objects.
To https://github.com/toniblyx/prowler.git
38ad3ca..2362518  devel -> devel
[09:52]toni@pumba:~/Downloads/prowler$
[12:46]toni@pumba:~/Downloads/prowler$
[12:46]toni@pumba:~/Downloads/prowler$
[12:46]toni@pumba:~/Downloads/prowler$ git status
On branch devel
Your branch is up to date with 'origin/devel'.

nothing to commit, working tree clean
[13:25]toni@pumba:~/Downloads/prowler$ git remote add upstream master
[13:25]toni@pumba:~/Downloads/prowler$ git status
On branch devel
Your branch is up to date with 'origin/devel'.

nothing to commit, working tree clean
[13:25]toni@pumba:~/Downloads/prowler$ git fetch upstream
fatal: 'master' does not appear to be a git repository
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
[13:26]toni@pumba:~/Downloads/prowler$ git remote add upstream origin/master
fatal: remote upstream already exists.
[13:26]toni@pumba:~/Downloads/prowler$
[13:26]toni@pumba:~/Downloads/prowler$
[13:26]toni@pumba:~/Downloads/prowler$ ls
LICENSE                      README.md                    include
LICENSE-APACHE-2.0           checks                       prowler
LICENSE-CC-BY-SA-4.0         groups                       util
LIST_OF_CHECKS_AND_GROUPS.md iam
[13:26]toni@pumba:~/Downloads/prowler$ cd ..
[13:26]toni@pumba:~/Downloads$ rm -fr prowler
[13:26]toni@pumba:~/Downloads$ git clone https://github.com/toniblyx/prowler
Cloning into 'prowler'...
remote: Counting objects: 1623, done.
remote: Total 1623 (delta 0), reused 0 (delta 0), pack-reused 1623
Receiving objects: 100% (1623/1623), 490.48 KiB | 3.77 MiB/s, done.
Resolving deltas: 100% (1044/1044), done.
[13:26]toni@pumba:~/Downloads$ cd prowler
[13:26]toni@pumba:~/Downloads/prowler$
[13:26]toni@pumba:~/Downloads/prowler$
[13:26]toni@pumba:~/Downloads/prowler$ git status
On branch master
Your branch is up to date with 'origin/master'.

nothing to commit, working tree clean
[13:27]toni@pumba:~/Downloads/prowler$ ./prowler -l
_
_ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_|v2.0-beta2
|_| the handy cloud security tool

Date: Thu Apr 19 13:33:02 EDT 2018

Colors code for results:  INFO (Information), PASS (Recommended value),  FAIL (Fix required)

1.0 Identity and Access Management - [group1] **********************

1.1  [check11] Avoid the use of the root account (Scored)

1.2  [check12] Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)

1.3  [check13] Ensure credentials unused for 90 days or greater are disabled (Scored)

1.4  [check14] Ensure access keys are rotated every 90 days or less (Scored)

1.5  [check15] Ensure IAM password policy requires at least one uppercase letter (Scored)

1.6  [check16] Ensure IAM password policy require at least one lowercase letter (Scored)

1.7  [check17] Ensure IAM password policy require at least one symbol (Scored)

1.8  [check18] Ensure IAM password policy require at least one number (Scored)

1.9  [check19] Ensure IAM password policy requires minimum length of 14 or greater (Scored)

1.10  [check110] Ensure IAM password policy prevents password reuse: 24 or greater (Scored)

1.11  [check111] Ensure IAM password policy expires passwords within 90 days or less (Scored)

1.12  [check112] Ensure no root account access key exists (Scored)

1.13  [check113] Ensure MFA is enabled for the root account (Scored)

1.14  [check114] Ensure hardware MFA is enabled for the root account (Scored)

1.15  [check115] Ensure security questions are registered in the AWS account (Not Scored)

1.16  [check116] Ensure IAM policies are attached only to groups or roles (Scored)

1.17  [check117] Enable detailed billing (Scored)

1.18  [check118] Ensure IAM Master and IAM Manager roles are active (Scored)

1.19  [check119] Maintain current contact details (Scored)

1.20  [check120] Ensure security contact information is registered (Scored)

1.21 [check121] Ensure IAM instance roles are used for AWS resource access from instances (Not Scored)

1.22  [check122] Ensure a support role has been created to manage incidents with AWS Support (Scored)

1.23 [check123] Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)

1.24  [check124] Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)

2.0 Logging - [group2] *********************************************

2.1  [check21] Ensure CloudTrail is enabled in all regions (Scored)

2.2  [check22] Ensure CloudTrail log file validation is enabled (Scored)

2.3  [check23] Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  [check24] Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  [check25] Ensure AWS Config is enabled in all regions (Scored)

2.6  [check26] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

2.7  [check27] Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)

2.8  [check28] Ensure rotation for customer created CMKs is enabled (Scored)

3.0 Monitoring - [group3] ******************************************

3.1  [check31] Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)

3.2  [check32] Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)

3.3  [check33] Ensure a log metric filter and alarm exist for usage of root account (Scored)

3.4  [check34] Ensure a log metric filter and alarm exist for IAM policy changes (Scored)

3.5  [check35] Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)

3.6  [check36] Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)

3.7  [check37] Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)

3.8  [check38] Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)

3.9  [check39] Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)

3.10  [check310] Ensure a log metric filter and alarm exist for security group changes (Scored)

3.11  [check311] Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)

3.12  [check312] Ensure a log metric filter and alarm exist for changes to network gateways (Scored)

3.13  [check313] Ensure a log metric filter and alarm exist for route table changes (Scored)

3.14  [check314] Ensure a log metric filter and alarm exist for VPC changes (Scored)

3.15  [check315] Ensure appropriate subscribers to each SNS topic (Not Scored)

4.0 Networking - [group4] ******************************************

4.1  [check41] Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)

4.2  [check42] Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)

4.3  [check43] Ensure VPC Flow Logging is Enabled in all VPCs (Scored)

4.4  [check44] Ensure the default security group of every VPC restricts all traffic (Scored)

4.5 [check45] Ensure routing tables for VPC peering are "least access" (Not Scored)

5.0 CIS Level 1 - [cislevel1] **************************************

1.1  [check11] Avoid the use of the root account (Scored)

1.2  [check12] Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)

1.3  [check13] Ensure credentials unused for 90 days or greater are disabled (Scored)

1.4  [check14] Ensure access keys are rotated every 90 days or less (Scored)

1.5  [check15] Ensure IAM password policy requires at least one uppercase letter (Scored)

1.6  [check16] Ensure IAM password policy require at least one lowercase letter (Scored)

1.7  [check17] Ensure IAM password policy require at least one symbol (Scored)

1.8  [check18] Ensure IAM password policy require at least one number (Scored)

1.9  [check19] Ensure IAM password policy requires minimum length of 14 or greater (Scored)

1.10  [check110] Ensure IAM password policy prevents password reuse: 24 or greater (Scored)

1.11  [check111] Ensure IAM password policy expires passwords within 90 days or less (Scored)

1.12  [check112] Ensure no root account access key exists (Scored)

1.13  [check113] Ensure MFA is enabled for the root account (Scored)

1.15  [check115] Ensure security questions are registered in the AWS account (Not Scored)

1.16  [check116] Ensure IAM policies are attached only to groups or roles (Scored)

1.17  [check117] Enable detailed billing (Scored)

1.18  [check118] Ensure IAM Master and IAM Manager roles are active (Scored)

1.19  [check119] Maintain current contact details (Scored)

1.20  [check120] Ensure security contact information is registered (Scored)

1.22  [check122] Ensure a support role has been created to manage incidents with AWS Support (Scored)

1.23 [check123] Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)

1.24  [check124] Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)

2.1  [check21] Ensure CloudTrail is enabled in all regions (Scored)

2.3  [check23] Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  [check24] Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  [check25] Ensure AWS Config is enabled in all regions (Scored)

2.6  [check26] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

3.1  [check31] Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)

3.2  [check32] Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)

3.3  [check33] Ensure a log metric filter and alarm exist for usage of root account (Scored)

3.4  [check34] Ensure a log metric filter and alarm exist for IAM policy changes (Scored)

3.5  [check35] Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)

3.8  [check38] Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)

3.12  [check312] Ensure a log metric filter and alarm exist for changes to network gateways (Scored)

3.13  [check313] Ensure a log metric filter and alarm exist for route table changes (Scored)

3.14  [check314] Ensure a log metric filter and alarm exist for VPC changes (Scored)

3.15  [check315] Ensure appropriate subscribers to each SNS topic (Not Scored)

4.1  [check41] Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)

4.2  [check42] Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)

6.0 CIS Level 2 - [cislevel2] **************************************

1.1  [check11] Avoid the use of the root account (Scored)

1.2  [check12] Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)

1.3  [check13] Ensure credentials unused for 90 days or greater are disabled (Scored)

1.4  [check14] Ensure access keys are rotated every 90 days or less (Scored)

1.5  [check15] Ensure IAM password policy requires at least one uppercase letter (Scored)

1.6  [check16] Ensure IAM password policy require at least one lowercase letter (Scored)

1.7  [check17] Ensure IAM password policy require at least one symbol (Scored)

1.8  [check18] Ensure IAM password policy require at least one number (Scored)

1.9  [check19] Ensure IAM password policy requires minimum length of 14 or greater (Scored)

1.10  [check110] Ensure IAM password policy prevents password reuse: 24 or greater (Scored)

1.11  [check111] Ensure IAM password policy expires passwords within 90 days or less (Scored)

1.12  [check112] Ensure no root account access key exists (Scored)

1.13  [check113] Ensure MFA is enabled for the root account (Scored)

1.14  [check114] Ensure hardware MFA is enabled for the root account (Scored)

1.15  [check115] Ensure security questions are registered in the AWS account (Not Scored)

1.16  [check116] Ensure IAM policies are attached only to groups or roles (Scored)

1.17  [check117] Enable detailed billing (Scored)

1.18  [check118] Ensure IAM Master and IAM Manager roles are active (Scored)

1.19  [check119] Maintain current contact details (Scored)

1.20  [check120] Ensure security contact information is registered (Scored)

1.21 [check121] Ensure IAM instance roles are used for AWS resource access from instances (Not Scored)

1.22  [check122] Ensure a support role has been created to manage incidents with AWS Support (Scored)

1.23 [check123] Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)

1.24  [check124] Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)

2.1  [check21] Ensure CloudTrail is enabled in all regions (Scored)

2.2  [check22] Ensure CloudTrail log file validation is enabled (Scored)

2.3  [check23] Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  [check24] Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  [check25] Ensure AWS Config is enabled in all regions (Scored)

2.6  [check26] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

2.7  [check27] Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)

2.8  [check28] Ensure rotation for customer created CMKs is enabled (Scored)

3.1  [check31] Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)

3.2  [check32] Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)

3.3  [check33] Ensure a log metric filter and alarm exist for usage of root account (Scored)

3.4  [check34] Ensure a log metric filter and alarm exist for IAM policy changes (Scored)

3.5  [check35] Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)

3.6  [check36] Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)

3.7  [check37] Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)

3.8  [check38] Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)

3.9  [check39] Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)

3.10  [check310] Ensure a log metric filter and alarm exist for security group changes (Scored)

3.11  [check311] Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)

3.12  [check312] Ensure a log metric filter and alarm exist for changes to network gateways (Scored)

3.13  [check313] Ensure a log metric filter and alarm exist for route table changes (Scored)

3.14  [check314] Ensure a log metric filter and alarm exist for VPC changes (Scored)

3.15  [check315] Ensure appropriate subscribers to each SNS topic (Not Scored)

4.1  [check41] Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)

4.2  [check42] Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)

4.3  [check43] Ensure VPC Flow Logging is Enabled in all VPCs (Scored)

4.4  [check44] Ensure the default security group of every VPC restricts all traffic (Scored)

4.5 [check45] Ensure routing tables for VPC peering are "least access" (Not Scored)

7.0 Extras - [extras] **********************************************

7.1 [extra71] Ensure users with AdministratorAccess policy have MFA tokens enabled (Not Scored) (Not part of CIS benchmark)

7.2 [extra72] Ensure there are no EBS Snapshots set as Public (Not Scored) (Not part of CIS benchmark)

7.3 [extra73] Ensure there are no S3 buckets open to the Everyone or Any AWS user (Not Scored) (Not part of CIS benchmark)

7.4 [extra74] Ensure there are no Security Groups without ingress filtering being used (Not Scored) (Not part of CIS benchmark)

7.5 [extra75] Ensure there are no Security Groups not being used (Not Scored) (Not part of CIS benchmark)

7.6 [extra75] Ensure there are no EC2 AMIs set as Public (Not Scored) (Not part of CIS benchmark)

7.7 [extra77] Ensure there are no ECR repositories set as Public (Not Scored) (Not part of CIS benchmark)

7.8 [extra78] Ensure there are no Public Accessible RDS instances (Not Scored) (Not part of CIS benchmark)

7.9 [extra79] Check for internet facing Elastic Load Balancers (Not Scored) (Not part of CIS benchmark)

7.10 [extra710] Check for internet facing EC2 Instances (Not Scored) (Not part of CIS benchmark)

7.11 [extra711] Check for Publicly Accessible Redshift Clusters (Not Scored) (Not part of CIS benchmark)

7.12 [extra712] Check if Amazon Macie is enabled (Not Scored) (Not part of CIS benchmark)

7.13 [extra713] Check if GuardDuty is enabled (Not Scored) (Not part of CIS benchmark)

7.14 [extra714] Check if CloudFront distributions have logging enabled (Not Scored) (Not part of CIS benchmark)

7.15 [extra715] Check if Elasticsearch Service domains have logging enabled (Not Scored) (Not part of CIS benchmark)

7.16 [extra716] Check if Elasticsearch Service domains allow open access (Not Scored) (Not part of CIS benchmark)

7.17 [extra717] Check if Elastic Load Balancers have logging enabled (Not Scored) (Not part of CIS benchmark)

7.18 [extra718] Check if S3 buckets have server access logging enabled (Not Scored) (Not part of CIS benchmark)

7.19 [extra719] Check if Route53 hosted zones are logging queries to CloudWatch Logs (Not Scored) (Not part of CIS benchmark)

7.20 [extra720] Check if Lambda functions invoke API operations are being recorded by CloudTrail (Not Scored) (Not part of CIS benchmark)

7.21 [extra721] Check if Redshift cluster has audit logging enabled (Not Scored) (Not part of CIS benchmark)

7.22 [extra722] Check if API Gateway has logging enabled (Not Scored) (Not part of CIS benchmark)

7.23 [extra723] Check if RDS Snapshots are public (Not Scored) (Not part of CIS benchmark)

7.24 [extra724] Check if ACM certificates have Certificate Transparency logging enabled (Not Scored) (Not part of CIS benchmark)

7.25 [extra725] Check if S3 buckets have Object-level logging enabled in CloudTrail (Not Scored) (Not part of CIS benchmark)

8.0 Forensics Readiness - [forensics-ready] ************************

2.1  [check21] Ensure CloudTrail is enabled in all regions (Scored)

2.2  [check22] Ensure CloudTrail log file validation is enabled (Scored)

2.3  [check23] Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  [check24] Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  [check25] Ensure AWS Config is enabled in all regions (Scored)

2.6  [check26] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

2.7  [check27] Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)

4.3  [check43] Ensure VPC Flow Logging is Enabled in all VPCs (Scored)

7.12 [extra712] Check if Amazon Macie is enabled (Not Scored) (Not part of CIS benchmark)

7.13 [extra713] Check if GuardDuty is enabled (Not Scored) (Not part of CIS benchmark)

7.14 [extra714] Check if CloudFront distributions have logging enabled (Not Scored) (Not part of CIS benchmark)

7.15 [extra715] Check if Elasticsearch Service domains have logging enabled (Not Scored) (Not part of CIS benchmark)

7.17 [extra717] Check if Elastic Load Balancers have logging enabled (Not Scored) (Not part of CIS benchmark)

7.18 [extra718] Check if S3 buckets have server access logging enabled (Not Scored) (Not part of CIS benchmark)

7.19 [extra719] Check if Route53 hosted zones are logging queries to CloudWatch Logs (Not Scored) (Not part of CIS benchmark)

7.20 [extra720] Check if Lambda functions invoke API operations are being recorded by CloudTrail (Not Scored) (Not part of CIS benchmark)

7.21 [extra721] Check if Redshift cluster has audit logging enabled (Not Scored) (Not part of CIS benchmark)

7.22 [extra722] Check if API Gateway has logging enabled (Not Scored) (Not part of CIS benchmark)

7.25 [extra725] Check if S3 buckets have Object-level logging enabled in CloudTrail (Not Scored) (Not part of CIS benchmark)

```
