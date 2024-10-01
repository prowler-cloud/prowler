import { Spacer } from "@nextui-org/react";
import React, { Suspense } from "react";

import {
  ColumnsFindings,
  DataTableFindings,
  SkeletonTableFindings,
} from "@/components/findings";
import { Header } from "@/components/ui";

export default async function Findings() {
  return (
    <>
      <Header title="Findings" icon="ph:list-checks-duotone" />
      <Spacer />
      <div className="flex w-full flex-col items-start overflow-hidden">
        <Spacer y={6} />
        <Suspense fallback={<SkeletonTableFindings />}>
          <SSRDataTable />
        </Suspense>
      </div>
    </>
  );
}

const SSRDataTable = async () => {
  return (
    <DataTableFindings
      columns={ColumnsFindings}
      data={[
        {
          id: "12345",
          attributes: {
            CheckTitle:
              "Ensure users of groups with AdministratorAccess policy have MFA tokens enabled",
            severity: "critical",
            status: "fail",
            region: "us-west-2",
            service: "cloudformation",
            account: "dev (106908755756)",
          },
          card: {
            resourceId:
              "StackSet-AWSControlTowerBP-BASELINE-CLOUDWATCH-57c2a54c-9a36-4af9-a910-d1adb424c62a",
            resourceLink:
              "https://app.prowler.pro/app/findings?date=2024-08-05&search=StackSet-AWSControlTowerBP-BASELINE-CLOUDWATCH-57c2a54c-9a36-4af9-a910-d1adb424c62a",
            resourceARN:
              "arn:aws:cloudformation:eu-west-1:714274078102:stack/StackSet-AWSControlTowerBP-BASELINE-CLOUDWATCH-57c2a54c-9a36-4af9-a910-d1adb424c62a/9656eda0-909c-11ec-8fb2-06f4f86422d5",
            checkId: "cloudformation_stack_outputs_find_secrets",
            checkLink:
              "https://app.prowler.pro/app/findings?date=2024-08-05&search=cloudformation_stack_outputs_find_secrets",
            type: ["Not applicable"],
            scanTime: "2024-07-17T09:55:14.191475Z",
            findingId: "ba123291-03a5-49a1-b962-6fdb1d2b9c9b",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-05&search=ba123291-03a5-49a1-b962-6fdb1d2b9c9b",
            details:
              "Potential secret found in Stack StackSet-AWSControlTowerBP-BASELINE-CLOUDWATCH-57c2a54c-9a36-4af9-a910-d1adb424c62a Outputs.",
            riskLink:
              "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html",
            riskDetails:
              "Secrets hardcoded into CloudFormation outputs can be used by malware and bad actors to gain lateral access to other services.",
            recommendationLink:
              "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html",
            recommendationDetails:
              "Implement automated detective control to scan accounts for passwords and secrets. Use secrets manager service to store and retrieve passwords and secrets.",
            referenceInformation: "CLI",
            referenceLink:
              "https://docs.prowler.com/checks/aws/secrets-policies/bc_aws_secrets_2/#cli-command",
          },
        },
        {
          id: "67891",
          attributes: {
            CheckTitle: "Find secrets in CloudFormation outputs",
            severity: "low",
            status: "success",
            region: "us-east-1",
            service: "cloudformation",
            account: "stg (987654321987)",
          },
          card: {
            resourceId: "<root_account>",
            resourceLink:
              "https://app.prowler.pro/app/findings?search=%3Croot_account%3E",
            resourceARN: "arn:aws:iam::714274078102:root",
            checkId: "iam_root_mfa_enabled",
            checkLink:
              "https://app.prowler.pro/app/findings?search=iam_root_mfa_enabled",
            type: [
              "Software and Configuration Checks",
              "Industry and Regulatory Standards",
              "CIS AWS Foundations Benchmark",
            ],
            scanTime: "2024-07-17T09:55:14.191475Z",
            findingId: "bc3a34e0-16f0-4ea1-ac62-f796c8af3448",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-05&search=bc3a34e0-16f0-4ea1-ac62-f796c8af3448",
            details: "MFA is not enabled for root account.",
            riskLink: "",
            riskDetails:
              "The root account is the most privileged user in an AWS account. MFA adds an extra layer of protection on top of a user name and password. With MFA enabled when a user signs in to an AWS website they will be prompted for their user name and password as well as for an authentication code from their AWS MFA device. When virtual MFA is used for root accounts it is recommended that the device used is NOT a personal device but rather a dedicated mobile device (tablet or phone) that is managed to be kept charged and secured independent of any individual personal devices. (non-personal virtual MFA) This lessens the risks of losing access to the MFA due to device loss / trade-in or if the individual owning the device is no longer employed at the company.",
            recommendationLink:
              "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa",
            recommendationDetails:
              "Using IAM console navigate to Dashboard and expand Activate MFA on your root account.",
            referenceInformation: "",
            referenceLink: "",
          },
        },
        {
          id: "67890",
          attributes: {
            CheckTitle:
              "Ensure S3 buckets with public read/write access are not allowed",
            severity: "high",
            status: "fail",
            region: "us-east-1",
            service: "s3",
            account: "prod (987654321012)",
          },
          card: {
            resourceId: "bucket-example-public-read-write",
            resourceLink:
              "https://app.prowler.pro/app/findings?date=2024-08-06&search=bucket-example-public-read-write",
            resourceARN: "arn:aws:s3:::bucket-example-public-read-write",
            checkId: "s3_bucket_public_access",
            checkLink:
              "https://app.prowler.pro/app/findings?date=2024-08-06&search=s3_bucket_public_access",
            type: ["Security"],
            scanTime: "2024-07-17T09:55:14.191475Z",
            findingId: "e7b3d6a2-39a1-4f0e-9b78-29f4e6f292d1",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-06&search=e7b3d6a2-39a1-4f0e-9b78-29f4e6f292d1",
            details:
              "S3 bucket example-public-read-write allows public read/write access.",
            riskLink:
              "https://docs.aws.amazon.com/AmazonS3/latest/dev/security-best-practices.html",
            riskDetails:
              "Publicly accessible S3 buckets can expose sensitive data and be exploited by attackers.",
            recommendationLink:
              "https://docs.aws.amazon.com/AmazonS3/latest/user-guide/block-public-access.html",
            recommendationDetails:
              "Use S3 Block Public Access to prevent public access to your S3 buckets.",
            referenceInformation: "AWS Console",
            referenceLink:
              "https://docs.prowler.com/checks/aws/s3-policies/bc_aws_s3_1/#console",
          },
        },
        {
          id: "11223",
          attributes: {
            CheckTitle:
              "Ensure IAM password policy requires minimum length of 12 characters",
            severity: "medium",
            status: "fail",
            region: "eu-central-1",
            service: "iam",
            account: "staging (123456789012)",
          },
          card: {
            resourceId: "password-policy",
            resourceLink:
              "https://app.prowler.pro/app/findings?date=2024-08-06&search=password-policy",
            resourceARN: "arn:aws:iam::123456789012:password-policy",
            checkId: "iam_password_policy_min_length",
            checkLink:
              "https://app.prowler.pro/app/findings?date=2024-08-06&search=iam_password_policy_min_length",
            type: ["Security"],
            scanTime: "2024-07-17T09:55:14.191475Z",
            findingId: "c2b3d1a4-7a9f-4d5c-a9ef-765a1d7f421c",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-06&search=c2b3d1a4-7a9f-4d5c-a9ef-765a1d7f421c",
            details:
              "IAM password policy does not require a minimum length of 12 characters.",
            riskLink:
              "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            riskDetails:
              "Weak password policies increase the risk of unauthorized access to AWS resources.",
            recommendationLink:
              "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
            recommendationDetails:
              "Enforce a minimum password length of 12 characters in your IAM password policy.",
            referenceInformation: "AWS CLI",
            referenceLink:
              "https://docs.prowler.com/checks/aws/iam-policies/bc_aws_iam_1/#cli-command",
          },
        },
        {
          id: "44556",
          attributes: {
            CheckTitle: "Ensure RDS instances are not publicly accessible",
            severity: "high",
            status: "muted",
            region: "ap-southeast-1",
            service: "rds",
            account: "prod (234567890123)",
          },
          card: {
            resourceId: "rds-instance-public-access",
            resourceLink:
              "https://app.prowler.pro/app/findings?date=2024-08-06&search=rds-instance-public-access",
            resourceARN:
              "arn:aws:rds:ap-southeast-1:234567890123:db:rds-instance-public-access",
            checkId: "rds_instance_public_access",
            checkLink:
              "https://app.prowler.pro/app/findings?date=2024-08-06&search=rds_instance_public_access",
            type: ["Security"],
            scanTime: "2024-07-17T09:55:14.191475Z",
            findingId: "f3b4c5d6-19a7-45d8-bc3e-8c5f6a7d8e9b",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-06&search=f3b4c5d6-19a7-45d8-bc3e-8c5f6a7d8e9b",
            details:
              "RDS instance is not publicly accessible, which adheres to security best practices.",
            riskLink:
              "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurity.html",
            riskDetails:
              "Publicly accessible RDS instances can be attacked by unauthorized users.",
            recommendationLink:
              "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.Scenarios.html",
            recommendationDetails:
              "Ensure RDS instances are not publicly accessible by placing them in private subnets.",
            referenceInformation: "AWS Console",
            referenceLink:
              "https://docs.prowler.com/checks/aws/rds-policies/bc_aws_rds_1/#console",
          },
        },
        {
          id: "77889",
          attributes: {
            CheckTitle: "Ensure EBS volumes are encrypted",
            severity: "critical",
            status: "fail",
            region: "eu-west-1",
            service: "ec2",
            account: "prod (345678901234)",
          },
          card: {
            resourceId: "volume-0123456789abcdef0",
            resourceLink:
              "https://app.prowler.pro/app/findings?date=2024-08-07&search=volume-0123456789abcdef0",
            resourceARN:
              "arn:aws:ec2:eu-west-1:345678901234:volume/volume-0123456789abcdef0",
            checkId: "ebs_volume_encryption",
            checkLink:
              "https://app.prowler.pro/app/findings?date=2024-08-07&search=ebs_volume_encryption",
            type: ["Encryption"],
            scanTime: "2024-07-17T09:55:14.191475Z",
            findingId: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-07&search=a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            details: "EBS volume volume-0123456789abcdef0 is not encrypted.",
            riskLink:
              "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
            riskDetails:
              "Unencrypted EBS volumes can expose sensitive data if compromised.",
            recommendationLink:
              "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
            recommendationDetails:
              "Enable encryption for EBS volumes using AWS-managed or customer-managed keys.",
            referenceInformation: "AWS CLI",
            referenceLink:
              "https://docs.prowler.com/checks/aws/ec2-policies/bc_aws_ec2_1/#cli-command",
          },
        },
        {
          id: "99100",
          attributes: {
            CheckTitle: "Ensure CloudTrail is enabled in all regions",
            severity: "critical",
            status: "fail",
            region: "us-west-2",
            service: "cloudtrail",
            account: "dev (456789012345)",
          },
          card: {
            resourceId: "cloudtrail-all-regions",
            resourceLink:
              "https://app.prowler.pro/app/findings?date=2024-08-07&search=cloudtrail-all-regions",
            resourceARN:
              "arn:aws:cloudtrail:us-west-2:456789012345:trail/cloudtrail-all-regions",
            checkId: "cloudtrail_all_regions_enabled",
            checkLink:
              "https://app.prowler.pro/app/findings?date=2024-08-07&search=cloudtrail_all_regions_enabled",
            type: ["Logging"],
            scanTime: "2024-07-17T09:55:14.191475Z",
            findingId: "b2c3d4e5-f6a7-8901-bcde-f123456789ab",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-07&search=b2c3d4e5-f6a7-8901-bcde-f123456789ab",
            details:
              "CloudTrail is not enabled for all regions in the account.",
            riskLink:
              "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-best-practices.html",
            riskDetails:
              "Without CloudTrail enabled in all regions, activities in non-monitored regions may go unnoticed.",
            recommendationLink:
              "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-using-console.html",
            recommendationDetails:
              "Enable CloudTrail across all regions to ensure comprehensive monitoring.",
            referenceInformation: "AWS Console",
            referenceLink:
              "https://docs.prowler.com/checks/aws/cloudtrail-policies/bc_aws_cloudtrail_1/#console",
          },
        },
        {
          id: "22334",
          attributes: {
            CheckTitle: "Ensure EC2 instances do not use outdated AMIs",
            severity: "medium",
            status: "fail",
            region: "us-east-1",
            service: "ec2",
            account: "prod (567890123456)",
          },
          card: {
            resourceId: "instance-ami-outdated",
            resourceLink:
              "https://app.prowler.pro/app/findings?date=2024-08-07&search=instance-ami-outdated",
            resourceARN:
              "arn:aws:ec2:us-east-1:567890123456:instance/instance-ami-outdated",
            checkId: "ec2_instance_outdated_ami",
            checkLink:
              "https://app.prowler.pro/app/findings?date=2024-08-07&search=ec2_instance_outdated_ami",
            type: ["Configuration"],
            scanTime: "2024-07-17T09:55:14.191475Z",
            findingId: "c3d4e5f6-a789-0123-bcde-f234567890ab",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-07&search=c3d4e5f6-a789-0123-bcde-f234567890ab",
            details:
              "EC2 instance instance-ami-outdated is using an outdated AMI.",
            riskLink:
              "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html",
            riskDetails:
              "Outdated AMIs may have unpatched vulnerabilities that can be exploited.",
            recommendationLink:
              "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-an-ami.html",
            recommendationDetails:
              "Update EC2 instances to use the latest AMIs with all security patches applied.",
            referenceInformation: "AWS CLI",
            referenceLink:
              "https://docs.prowler.com/checks/aws/ec2-policies/bc_aws_ec2_2/#cli-command",
          },
        },
        {
          id: "55667",
          attributes: {
            CheckTitle:
              "Ensure CloudWatch alarms exist for critical system events",
            severity: "high",
            status: "muted",
            region: "eu-west-2",
            service: "cloudwatch",
            account: "prod (678901234567)",
          },
          card: {
            resourceId: "cloudwatch-alarms",
            resourceLink:
              "https://app.prowler.pro/app/findings?date=2024-08-08&search=cloudwatch-alarms",
            resourceARN:
              "arn:aws:cloudwatch:eu-west-2:678901234567:alarm/cloudwatch-alarms",
            checkId: "cloudwatch_alarms_for_critical_events",
            checkLink:
              "https://app.prowler.pro/app/findings?date=2024-08-08&search=cloudwatch_alarms_for_critical_events",
            type: ["Monitoring"],
            scanTime: "2024-07-17T09:55:14.191475Z",
            findingId: "d4e5f6a7-8901-bcde-f345678901ab",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-08&search=d4e5f6a7-8901-bcde-f345678901ab",
            details:
              "CloudWatch alarms are correctly configured for critical system events.",
            riskLink:
              "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatchAlarms.html",
            riskDetails:
              "Without alarms for critical events, key issues may go unnoticed, leading to outages.",
            recommendationLink:
              "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create_Alarm.html",
            recommendationDetails:
              "Ensure alarms are set up for critical events to trigger timely notifications.",
            referenceInformation: "AWS Console",
            referenceLink:
              "https://docs.prowler.com/checks/aws/cloudwatch-policies/bc_aws_cloudwatch_1/#console",
          },
        },
        {
          id: "88900",
          attributes: {
            CheckTitle: "Ensure IAM users have least privilege permissions",
            severity: "medium",
            status: "fail",
            region: "ap-northeast-1",
            service: "iam",
            account: "dev (789012345678)",
          },
          card: {
            resourceId: "iam-user-least-privilege",
            resourceLink:
              "https://app.prowler.pro/app/findings?date=2024-08-08&search=iam-user-least-privilege",
            resourceARN:
              "arn:aws:iam::789012345678:user/iam-user-least-privilege",
            checkId: "iam_user_least_privilege",
            checkLink:
              "https://app.prowler.pro/app/findings?date=2024-08-08&search=iam_user_least_privilege",
            type: ["Security"],
            scanTime: "2024-07-17T09:55:14.191475Z",
            findingId: "e5f6a7b8-9012-bcde-f456789012ab",
            findingLink:
              "https://app.prowler.pro/app/findings?date=2024-08-08&search=e5f6a7b8-9012-bcde-f456789012ab",
            details:
              "IAM user iam-user-least-privilege has more permissions than necessary.",
            riskLink:
              "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            riskDetails:
              "Excessive permissions increase the risk of privilege escalation and security breaches.",
            recommendationLink:
              "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
            recommendationDetails:
              "Apply the principle of least privilege to IAM users by restricting their permissions to the minimum necessary.",
            referenceInformation: "AWS CLI",
            referenceLink:
              "https://docs.prowler.com/checks/aws/iam-policies/bc_aws_iam_2/#cli-command",
          },
        },
      ]}
    />
  );
};
