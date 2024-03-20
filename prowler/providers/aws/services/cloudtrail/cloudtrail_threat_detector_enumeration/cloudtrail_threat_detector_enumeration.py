from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)

THREAT_DETECTION_DAYS = cloudtrail_client.audit_config.get("threat_detection_days", 1)
ENUMERATION_ACTIONS = [
    "DescribeAccessEntry",
    "DescribeAccountAttributes",
    "DescribeAvailabilityZones",
    "DescribeBundleTasks",
    "DescribeCarrierGateways",
    "DescribeClientVpnRoutes",
    "DescribeCluster",
    "DescribeDhcpOptions",
    "DescribeFlowLogs",
    "DescribeImages",
    "DescribeInstanceAttribute",
    "DescribeInstanceInformation",
    "DescribeInstanceTypes",
    "DescribeInstances",
    "DescribeInstances",
    "DescribeKeyPairs",
    "DescribeLogGroups",
    "DescribeLogStreams",
    "DescribeOrganization",
    "DescribeRegions",
    "DescribeSecurityGroups",
    "DescribeSnapshotAttribute",
    "DescribeSnapshotTierStatus",
    "DescribeSubscriptionFilters",
    "DescribeTransitGatewayMulticastDomains",
    "DescribeVolumes",
    "DescribeVolumesModifications",
    "DescribeVpcEndpointConnectionNotifications",
    "DescribeVpcs",
    "GetAccount",
    "GetAccountAuthorizationDetails",
    "GetAccountSendingEnabled",
    "GetBucketAcl",
    "GetBucketLogging",
    "GetBucketPolicy",
    "GetBucketReplication",
    "GetBucketVersioning",
    "GetCallerIdentity",
    "GetCertificate",
    "GetConsoleScreenshot",
    "GetCostAndUsage",
    "GetDetector",
    "GetEbsDefaultKmsKeyId",
    "GetEbsEncryptionByDefault",
    "GetFindings",
    "GetFlowLogsIntegrationTemplate",
    "GetIdentityVerificationAttributes",
    "GetInstances",
    "GetIntrospectionSchema",
    "GetLaunchTemplateData",
    "GetLaunchTemplateData",
    "GetLogRecord",
    "GetParameters",
    "GetPolicyVersion",
    "GetPublicAccessBlock",
    "GetQueryResults",
    "GetRegions",
    "GetSMSAttributes",
    "GetSMSSandboxAccountStatus",
    "GetSendQuota",
    "GetTransitGatewayRouteTableAssociations",
    "GetUserPolicy",
    "HeadObject",
    "ListAccessKeys",
    "ListAccounts",
    "ListAllMyBuckets",
    "ListAssociatedAccessPolicies",
    "ListAttachedUserPolicies",
    "ListClusters",
    "ListDetectors",
    "ListDomains",
    "ListFindings",
    "ListHostedZones",
    "ListIPSets",
    "ListIdentities",
    "ListInstanceProfiles",
    "ListObjects",
    "ListOrganizationalUnitsForParent",
    "ListOriginationNumbers",
    "ListPolicyVersions",
    "ListRoles",
    "ListRoles",
    "ListRules",
    "ListServiceQuotas",
    "ListSubscriptions",
    "ListTargetsByRule",
    "ListTopics",
    "ListUsers",
    "LookupEvents",
    "Search",
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
