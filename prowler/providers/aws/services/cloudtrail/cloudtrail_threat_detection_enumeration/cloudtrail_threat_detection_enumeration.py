from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
    get_cloudtrail_account_resource,
    get_cloudtrail_threat_detection_identities,
)

default_threat_detection_enumeration_actions = [
    "CreateIndex",
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
    "ListResources",
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


class cloudtrail_threat_detection_enumeration(Check):
    """Detect potential AWS API enumeration activity recorded by CloudTrail."""

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate CloudTrail events for potential enumeration activity.

        Returns:
            list[Check_Report_AWS]: Reports for detected identities or the account.
        """
        findings = []
        threshold = cloudtrail_client.audit_config.get(
            "threat_detection_enumeration_threshold", 0.3
        )
        threat_detection_minutes = cloudtrail_client.audit_config.get(
            "threat_detection_enumeration_minutes", 1440
        )
        enumeration_actions = cloudtrail_client.audit_config.get(
            "threat_detection_enumeration_actions",
            default_threat_detection_enumeration_actions,
        )
        found_potential_enumeration = False
        potential_enumeration = get_cloudtrail_threat_detection_identities(
            cloudtrail_client, enumeration_actions, threat_detection_minutes
        )

        if potential_enumeration is None:
            resource = get_cloudtrail_account_resource(
                cloudtrail_client.audited_account,
                cloudtrail_client.audited_account_arn,
                cloudtrail_client.region,
            )
            report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
            report.status = "MANUAL"
            report.status_extended = "Cannot evaluate CloudTrail threat detection because CloudTrail trails or events could not be retrieved in at least one audited region. Verify that the scanning credentials are allowed to call cloudtrail:DescribeTrails and cloudtrail:LookupEvents."
            return [report]

        for resource, actions in potential_enumeration.values():
            identity_threshold = round(len(actions) / len(enumeration_actions), 2)
            if len(actions) / len(enumeration_actions) > threshold:
                found_potential_enumeration = True
                report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
                report.status = "FAIL"
                report.status_extended = f"Potential enumeration attack detected from AWS {resource.identity_type} {resource.name} with a threshold of {identity_threshold}."
                findings.append(report)
        if not found_potential_enumeration:
            resource = get_cloudtrail_account_resource(
                cloudtrail_client.audited_account,
                cloudtrail_client.audited_account_arn,
                cloudtrail_client.region,
            )
            report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
            report.status = "PASS"
            report.status_extended = "No potential enumeration attack detected."
            findings.append(report)
        return findings
