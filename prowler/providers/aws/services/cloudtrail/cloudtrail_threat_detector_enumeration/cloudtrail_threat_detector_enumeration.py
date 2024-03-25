import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)

ENTROPY_THRESHOLD = 0.7
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
        potential_enumeration = {}
        found_potential_enumeration = False
        for trail in cloudtrail_client.trails:
            for event_name in ENUMERATION_ACTIONS:
                for event_log in cloudtrail_client.__lookup_events__(
                    trail=trail,
                    event_name=event_name,
                    days=THREAT_DETECTION_DAYS,
                ):
                    event_log = json.loads(event_log["CloudTrailEvent"])
                    if ".amazonaws.com" not in event_log["sourceIPAddress"]:
                        if event_log["sourceIPAddress"] not in potential_enumeration:
                            potential_enumeration[event_log["sourceIPAddress"]] = set()
                        potential_enumeration[event_log["sourceIPAddress"]].add(
                            event_name
                        )
        for source_ip, actions in potential_enumeration.items():
            if len(actions) / len(ENUMERATION_ACTIONS) > ENTROPY_THRESHOLD:
                found_potential_enumeration = True
                report = Check_Report_AWS(self.metadata())
                report.region = trail.region
                report.resource_id = trail.name
                report.resource_arn = trail.arn
                report.resource_tags = trail.tags
                report.status = "FAIL"
                report.status_extended = f"Potential privilege escalation detected from source IP {source_ip} with an entropy of {ENTROPY_THRESHOLD}."
                findings.append(report)
        if not found_potential_enumeration:
            report = Check_Report_AWS(self.metadata())
            report.region = trail.region
            report.resource_id = trail.name
            report.resource_arn = trail.arn
            report.resource_tags = trail.tags
            report.status = "PASS"
            report.status_extended = "No potential privilege escalation detected."
            findings.append(report)
        return findings
