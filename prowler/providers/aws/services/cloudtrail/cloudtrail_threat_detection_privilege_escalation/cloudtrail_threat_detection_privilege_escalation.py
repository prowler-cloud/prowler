from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
    get_cloudtrail_account_resource,
    get_cloudtrail_threat_detection_identities,
)

default_threat_detection_privilege_escalation_actions = [
    "AddPermission",
    "AddRoleToInstanceProfile",
    "AddUserToGroup",
    "AssociateAccessPolicy",
    "AssumeRole",
    "AttachGroupPolicy",
    "AttachRolePolicy",
    "AttachUserPolicy",
    "ChangePassword",
    "CreateAccessEntry",
    "CreateAccessKey",
    "CreateDevEndpoint",
    "CreateEventSourceMapping",
    "CreateFunction",
    "CreateGroup",
    "CreateJob",
    "CreateKeyPair",
    "CreateLoginProfile",
    "CreatePipeline",
    "CreatePolicyVersion",
    "CreateRole",
    "CreateStack",
    "DeleteRolePermissionsBoundary",
    "DeleteRolePolicy",
    "DeleteUserPermissionsBoundary",
    "DeleteUserPolicy",
    "DetachRolePolicy",
    "DetachUserPolicy",
    "GetCredentialsForIdentity",
    "GetId",
    "GetPolicyVersion",
    "GetUserPolicy",
    "Invoke",
    "ModifyInstanceAttribute",
    "PassRole",
    "PutGroupPolicy",
    "PutPipelineDefinition",
    "PutRolePermissionsBoundary",
    "PutRolePolicy",
    "PutUserPermissionsBoundary",
    "PutUserPolicy",
    "ReplaceIamInstanceProfileAssociation",
    "RunInstances",
    "SetDefaultPolicyVersion",
    "UpdateAccessKey",
    "UpdateAssumeRolePolicy",
    "UpdateDevEndpoint",
    "UpdateEventSourceMapping",
    "UpdateFunctionCode",
    "UpdateJob",
    "UpdateLoginProfile",
]


class cloudtrail_threat_detection_privilege_escalation(Check):
    """Detect potential privilege-escalation activity recorded by CloudTrail."""

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate CloudTrail events for potential privilege-escalation activity.

        Returns:
            list[Check_Report_AWS]: Reports for detected identities or the account.
        """
        findings = []
        threshold = cloudtrail_client.audit_config.get(
            "threat_detection_privilege_escalation_threshold", 0.2
        )
        threat_detection_minutes = cloudtrail_client.audit_config.get(
            "threat_detection_privilege_escalation_minutes", 1440
        )
        privilege_escalation_actions = cloudtrail_client.audit_config.get(
            "threat_detection_privilege_escalation_actions",
            default_threat_detection_privilege_escalation_actions,
        )

        found_potential_privilege_escalation = False
        potential_privilege_escalation = get_cloudtrail_threat_detection_identities(
            cloudtrail_client,
            privilege_escalation_actions,
            threat_detection_minutes,
        )
        if potential_privilege_escalation is None:
            resource = get_cloudtrail_account_resource(
                cloudtrail_client.audited_account,
                cloudtrail_client.audited_account_arn,
                cloudtrail_client.region,
            )
            report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
            report.status = "MANUAL"
            report.status_extended = "Cannot evaluate CloudTrail threat detection because CloudTrail trails or events could not be retrieved in at least one audited region. Verify that the scanning credentials are allowed to call cloudtrail:DescribeTrails and cloudtrail:LookupEvents."
            return [report]
        for resource, actions in potential_privilege_escalation.values():
            identity_threshold = round(
                len(actions) / len(privilege_escalation_actions), 2
            )
            if len(actions) / len(privilege_escalation_actions) > threshold:
                found_potential_privilege_escalation = True
                report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
                report.status = "FAIL"
                report.status_extended = f"Potential privilege escalation attack detected from AWS {resource.identity_type} {resource.name} with a threshold of {identity_threshold}."
                findings.append(report)
        if not found_potential_privilege_escalation:
            resource = get_cloudtrail_account_resource(
                cloudtrail_client.audited_account,
                cloudtrail_client.audited_account_arn,
                cloudtrail_client.region,
            )
            report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
            report.status = "PASS"
            report.status_extended = (
                "No potential privilege escalation attack detected."
            )
            findings.append(report)
        return findings
