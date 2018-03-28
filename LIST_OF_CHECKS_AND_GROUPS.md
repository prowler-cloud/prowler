```                      _
 _ __  _ __ _____      _| | ___ _ __
| '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|
| |_) | | | (_) \ V  V /| |  __/ |
| .__/|_|  \___/ \_/\_/ |_|\___|_|v2.0
|_| the handy cloud security tool

Date: Tue Mar 27 18:38:53 EDT 2018

Colors code for results:  INFO (Information), PASS (Recommended value),  FAIL (Fix required)

1.0 (group1) Identity and Access Management ****************************************

1.1  Avoid the use of the root account (Scored)

1.2  Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)

1.3  Ensure credentials unused for 90 days or greater are disabled (Scored)

1.4  Ensure access keys are rotated every 90 days or less (Scored)

1.5  Ensure IAM password policy requires at least one uppercase letter (Scored)

1.6  Ensure IAM password policy require at least one lowercase letter (Scored)

1.7  Ensure IAM password policy require at least one symbol (Scored)

1.8  Ensure IAM password policy require at least one number (Scored)

1.9  Ensure IAM password policy requires minimum length of 14 or greater (Scored)

1.10  Ensure IAM password policy prevents password reuse: 24 or greater (Scored)

1.11  Ensure IAM password policy expires passwords within 90 days or less (Scored)

1.12  Ensure no root account access key exists (Scored)

1.13  Ensure MFA is enabled for the root account (Scored)

1.14  Ensure hardware MFA is enabled for the root account (Scored)

1.15  Ensure security questions are registered in the AWS account (Not Scored)

1.16  Ensure IAM policies are attached only to groups or roles (Scored)

1.17  Enable detailed billing (Scored)

1.18  Ensure IAM Master and IAM Manager roles are active (Scored)

1.19  Maintain current contact details (Scored)

1.20  Ensure security contact information is registered (Scored)

1.21 Ensure IAM instance roles are used for AWS resource access from instances (Not Scored)

1.22  Ensure a support role has been created to manage incidents with AWS Support (Scored)

1.23 Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)

1.24  Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)

2.0 (group2) Logging ***************************************************************

2.1  Ensure CloudTrail is enabled in all regions (Scored)

2.2  Ensure CloudTrail log file validation is enabled (Scored)

2.3  Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  Ensure AWS Config is enabled in all regions (Scored)

2.6  Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

2.7  Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)

2.8  Ensure rotation for customer created CMKs is enabled (Scored)

3.0 (group3) Monitoring ************************************************************

3.1  Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)

3.2  Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)

3.3  Ensure a log metric filter and alarm exist for usage of root account (Scored)

3.4  Ensure a log metric filter and alarm exist for IAM policy changes (Scored)

3.5  Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)

3.6  Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)

3.7  Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)

3.8  Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)

3.9  Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)

3.10  Ensure a log metric filter and alarm exist for security group changes (Scored)

3.11  Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)

3.12  Ensure a log metric filter and alarm exist for changes to network gateways (Scored)

3.13  Ensure a log metric filter and alarm exist for route table changes (Scored)

3.14  Ensure a log metric filter and alarm exist for VPC changes (Scored)

3.15  Ensure appropriate subscribers to each SNS topic (Not Scored)

4.0 (group4) Networking ************************************************************

4.1  Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)

4.2  Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)

4.3  Ensure VPC Flow Logging is Enabled in all VPCs (Scored)

4.4  Ensure the default security group of every VPC restricts all traffic (Scored)

4.5 Ensure routing tables for VPC peering are "least access" (Not Scored)

5.0 (cislevel1) CIS Level 1 **********************************************************

1.1  Avoid the use of the root account (Scored)

1.2  Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)

1.3  Ensure credentials unused for 90 days or greater are disabled (Scored)

1.4  Ensure access keys are rotated every 90 days or less (Scored)

1.5  Ensure IAM password policy requires at least one uppercase letter (Scored)

1.6  Ensure IAM password policy require at least one lowercase letter (Scored)

1.7  Ensure IAM password policy require at least one symbol (Scored)

1.8  Ensure IAM password policy require at least one number (Scored)

1.9  Ensure IAM password policy requires minimum length of 14 or greater (Scored)

1.10  Ensure IAM password policy prevents password reuse: 24 or greater (Scored)

1.11  Ensure IAM password policy expires passwords within 90 days or less (Scored)

1.12  Ensure no root account access key exists (Scored)

1.13  Ensure MFA is enabled for the root account (Scored)

1.15  Ensure security questions are registered in the AWS account (Not Scored)

1.16  Ensure IAM policies are attached only to groups or roles (Scored)

1.17  Enable detailed billing (Scored)

1.18  Ensure IAM Master and IAM Manager roles are active (Scored)

1.19  Maintain current contact details (Scored)

1.20  Ensure security contact information is registered (Scored)

1.22  Ensure a support role has been created to manage incidents with AWS Support (Scored)

1.23 Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)

1.24  Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)

2.1  Ensure CloudTrail is enabled in all regions (Scored)

2.3  Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  Ensure AWS Config is enabled in all regions (Scored)

2.6  Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

3.1  Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)

3.2  Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)

3.3  Ensure a log metric filter and alarm exist for usage of root account (Scored)

3.4  Ensure a log metric filter and alarm exist for IAM policy changes (Scored)

3.5  Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)

3.8  Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)

3.12  Ensure a log metric filter and alarm exist for changes to network gateways (Scored)

3.13  Ensure a log metric filter and alarm exist for route table changes (Scored)

3.14  Ensure a log metric filter and alarm exist for VPC changes (Scored)

3.15  Ensure appropriate subscribers to each SNS topic (Not Scored)

4.1  Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)

4.2  Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)

6.0 (cislevel2) CIS Level 2 **********************************************************

1.1  Avoid the use of the root account (Scored)

1.2  Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)

1.3  Ensure credentials unused for 90 days or greater are disabled (Scored)

1.4  Ensure access keys are rotated every 90 days or less (Scored)

1.5  Ensure IAM password policy requires at least one uppercase letter (Scored)

1.6  Ensure IAM password policy require at least one lowercase letter (Scored)

1.7  Ensure IAM password policy require at least one symbol (Scored)

1.8  Ensure IAM password policy require at least one number (Scored)

1.9  Ensure IAM password policy requires minimum length of 14 or greater (Scored)

1.10  Ensure IAM password policy prevents password reuse: 24 or greater (Scored)

1.11  Ensure IAM password policy expires passwords within 90 days or less (Scored)

1.12  Ensure no root account access key exists (Scored)

1.13  Ensure MFA is enabled for the root account (Scored)

1.14  Ensure hardware MFA is enabled for the root account (Scored)

1.15  Ensure security questions are registered in the AWS account (Not Scored)

1.16  Ensure IAM policies are attached only to groups or roles (Scored)

1.17  Enable detailed billing (Scored)

1.18  Ensure IAM Master and IAM Manager roles are active (Scored)

1.19  Maintain current contact details (Scored)

1.20  Ensure security contact information is registered (Scored)

1.21 Ensure IAM instance roles are used for AWS resource access from instances (Not Scored)

1.22  Ensure a support role has been created to manage incidents with AWS Support (Scored)

1.23 Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)

1.24  Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)

2.1  Ensure CloudTrail is enabled in all regions (Scored)

2.2  Ensure CloudTrail log file validation is enabled (Scored)

2.3  Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  Ensure AWS Config is enabled in all regions (Scored)

2.6  Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

2.7  Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)

2.8  Ensure rotation for customer created CMKs is enabled (Scored)

3.1  Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)

3.2  Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)

3.3  Ensure a log metric filter and alarm exist for usage of root account (Scored)

3.4  Ensure a log metric filter and alarm exist for IAM policy changes (Scored)

3.5  Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)

3.6  Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)

3.7  Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)

3.8  Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)

3.9  Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)

3.10  Ensure a log metric filter and alarm exist for security group changes (Scored)

3.11  Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)

3.12  Ensure a log metric filter and alarm exist for changes to network gateways (Scored)

3.13  Ensure a log metric filter and alarm exist for route table changes (Scored)

3.14  Ensure a log metric filter and alarm exist for VPC changes (Scored)

3.15  Ensure appropriate subscribers to each SNS topic (Not Scored)

4.1  Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)

4.2  Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)

4.3  Ensure VPC Flow Logging is Enabled in all VPCs (Scored)

4.4  Ensure the default security group of every VPC restricts all traffic (Scored)

4.5 Ensure routing tables for VPC peering are "least access" (Not Scored)

7.0 (extras) Extras ****************************************************************

7.1 Ensure users with AdministratorAccess policy have MFA tokens enabled (Not Scored) (Not part of CIS benchmark)

7.2 Ensure there are no EBS Snapshots set as Public (Not Scored) (Not part of CIS benchmark)

7.3 Ensure there are no S3 buckets open to the Everyone or Any AWS user (Not Scored) (Not part of CIS benchmark)

7.4 Ensure there are no Security Groups without ingress filtering being used (Not Scored) (Not part of CIS benchmark)

7.5 Ensure there are no Security Groups not being used (Not Scored) (Not part of CIS benchmark)

7.6 Ensure there are no EC2 AMIs set as Public (Not Scored) (Not part of CIS benchmark)

7.7 Ensure there are no ECR repositories set as Public (Not Scored) (Not part of CIS benchmark)

7.8 Ensure there are no Public Accessible RDS instances (Not Scored) (Not part of CIS benchmark)

7.9 Check for internet facing Elastic Load Balancers (Not Scored) (Not part of CIS benchmark)

7.10 Check for internet facing EC2 Instances (Not Scored) (Not part of CIS benchmark)

7.11 Check for Publicly Accessible Redshift Clusters (Not Scored) (Not part of CIS benchmark)

7.12 Check if Amazon Macie is enabled (Not Scored) (Not part of CIS benchmark)

7.13 Check if GuardDuty is enabled (Not Scored) (Not part of CIS benchmark)

7.14 Check if CloudFront distributions have logging enabled (Not Scored) (Not part of CIS benchmark)

7.15 Check if Elasticsearch Service domains have logging enabled (Not Scored) (Not part of CIS benchmark)

7.16 Check if Elasticsearch Service domains allow open access (Not Scored) (Not part of CIS benchmark)

7.17 Check if Elastic Load Balancers have logging enabled (Not Scored) (Not part of CIS benchmark)

7.18 Check if S3 buckets have server access logging enabled (Not Scored) (Not part of CIS benchmark)

7.19 Check if Route53 hosted zones are logging queries to CloudWatch Logs (Not Scored) (Not part of CIS benchmark)

7.20 Check if Lambda functions invoke API operations are being recorded by CloudTrail (Not Scored) (Not part of CIS benchmark)

7.21 Check if Redshift cluster has audit logging enabled (Not Scored) (Not part of CIS benchmark)

7.22 Check if API Gateway has logging enabled (Not Scored) (Not part of CIS benchmark)

7.23 Check if RDS Snapshots are public (Not Scored) (Not part of CIS benchmark)

8.0 (forensics-ready) Forensics Readiness ***************************************************

2.1  Ensure CloudTrail is enabled in all regions (Scored)

2.2  Ensure CloudTrail log file validation is enabled (Scored)

2.3  Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)

2.4  Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)

2.5  Ensure AWS Config is enabled in all regions (Scored)

2.6  Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)

2.7  Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)

4.3  Ensure VPC Flow Logging is Enabled in all VPCs (Scored)

7.12 Check if Amazon Macie is enabled (Not Scored) (Not part of CIS benchmark)

7.13 Check if GuardDuty is enabled (Not Scored) (Not part of CIS benchmark)

7.14 Check if CloudFront distributions have logging enabled (Not Scored) (Not part of CIS benchmark)

7.15 Check if Elasticsearch Service domains have logging enabled (Not Scored) (Not part of CIS benchmark)

7.17 Check if Elastic Load Balancers have logging enabled (Not Scored) (Not part of CIS benchmark)

7.18 Check if S3 buckets have server access logging enabled (Not Scored) (Not part of CIS benchmark)

7.19 Check if Route53 hosted zones are logging queries to CloudWatch Logs (Not Scored) (Not part of CIS benchmark)

7.20 Check if Lambda functions invoke API operations are being recorded by CloudTrail (Not Scored) (Not part of CIS benchmark)

7.21 Check if Redshift cluster has audit logging enabled (Not Scored) (Not part of CIS benchmark)

7.22 Check if API Gateway has logging enabled (Not Scored) (Not part of CIS benchmark)

7.23 Check if RDS Snapshots are public (Not Scored) (Not part of CIS benchmark)

7.24 Check if ACM certificates have Certificate Transparency logging enabled (Not Scored) (Not part of CIS benchmark)
```
