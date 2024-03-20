from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)

THREAT_DETECTION_DAYS = cloudtrail_client.audit_config.get("threat_detection_days", 1)
ENUMERATION_ACTIONS = [
    "acm:GetCertificate",
    "appsync:GetIntrospectionSchema",
    "athena:GetQueryResults",
    "ce:GetCostAndUsage",
    "cloudtrail:LookupEvents",
    "ec2:DescribeAccountAttributes",
    "ec2:DescribeAvailabilityZones",
    "ec2:DescribeBundleTasks",
    "ec2:DescribeCarrierGateways",
    "ec2:DescribeClientVpnRoutes",
    "ec2:DescribeDhcpOptions",
    "ec2:DescribeFlowLogs",
    "ec2:DescribeImages",
    "ec2:DescribeInstanceAttribute",
    "ec2:DescribeInstanceTypes",
    "ec2:DescribeInstances",
    "ec2:DescribeInstances",
    "ec2:DescribeKeyPairs",
    "ec2:DescribeRegions",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSnapshotAttribute",
    "ec2:DescribeSnapshotTierStatus",
    "ec2:DescribeTransitGatewayMulticastDomains",
    "ec2:DescribeVolumes",
    "ec2:DescribeVolumesModifications",
    "ec2:DescribeVpcEndpointConnectionNotifications",
    "ec2:DescribeVpcs",
    "ec2:GetConsoleScreenshot",
    "ec2:GetEbsDefaultKmsKeyId",
    "ec2:GetEbsEncryptionByDefault",
    "ec2:GetFlowLogsIntegrationTemplate",
    "ec2:GetLaunchTemplateData",
    "ec2:GetLaunchTemplateData",
    "ec2:GetTransitGatewayRouteTableAssociations",
    "eks:DescribeAccessEntry",
    "eks:DescribeCluster",
    "eks:ListAssociatedAccessPolicies",
    "eks:ListClusters",
    "events:ListRules",
    "events:ListTargetsByRule",
    "guardduty:GetDetector",
    "guardduty:GetFindings",
    "guardduty:ListDetectors",
    "guardduty:ListFindings",
    "guardduty:ListIPSets",
    "iam:GetAccountAuthorizationDetails",
    "iam:GetCallerIdentity",
    "iam:GetPolicyVersion",
    "iam:GetUserPolicy",
    "iam:ListAccessKeys",
    "iam:ListAttachedUserPolicies",
    "iam:ListInstanceProfiles",
    "iam:ListPolicyVersions",
    "iam:ListRoles",
    "iam:ListRoles",
    "iam:ListUserPoliciesiam:ListUsers",
    "lightsail:GetInstances",
    "lightsail:GetRegions",
    "logs:DescribeLogGroups",
    "logs:DescribeLogStreams",
    "logs:DescribeSubscriptionFilters",
    "logs:GetLogRecord",
    "organizations:DescribeOrganization",
    "organizations:ListAccounts",
    "organizations:ListOrganizationalUnitsForParent",
    "resource-explorer-2:Search",
    "route53:ListDomains",
    "route53:ListHostedZones",
    "s3:GetBucketAcl",
    "s3:GetBucketLogging",
    "s3:GetBucketPolicy",
    "s3:GetBucketReplication",
    "s3:GetBucketVersioning",
    "s3:GetPublicAccessBlock",
    "s3:HeadObject",
    "s3:ListAllMyBuckets",
    "s3:ListObjects",
    "servicequotas:ListServiceQuotas",
    "ses:GetAccount",
    "ses:GetAccountSendingEnabled",
    "ses:GetIdentityVerificationAttributes",
    "ses:GetSendQuota",
    "ses:ListIdentities",
    "sns:GetSMSAttributes",
    "sns:GetSMSSandboxAccountStatus",
    "sns:ListOriginationNumbers",
    "sns:ListSubscriptions",
    "sns:ListTopics",
    "ssm:DescribeInstanceInformation",
    "ssm:GetParameters",
]


class cloudtrail_threat_detector_enumeration(Check):
    def execute(self):
        findings = []
        for trail in cloudtrail_client.trails:
            print(
                cloudtrail_client.__lookup_events__(
                    trail=trail,
                    event_names=["ConsoleLogin"],
                    days=THREAT_DETECTION_DAYS,
                )
            )
            report = Check_Report_AWS(self.metadata())
            report.region = trail.region
            report.resource_id = trail.name
            report.resource_arn = trail.arn
            report.resource_tags = trail.tags
            report.status = "FAIL"
            report.status_extended = (
                f"Trail {trail.name} does not have insight selectors and it is logging."
            )
            if trail.has_insight_selectors:
                report.status = "PASS"
                report.status_extended = (
                    f"Trail {trail.name} has insight selectors and it is logging."
                )
            findings.append(report)
        return findings
