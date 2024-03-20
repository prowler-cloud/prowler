from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)

THREAT_DETECTION_DAYS = cloudtrail_client.audit_config.get("threat_detection_days", 1)
PRIVILEGE_ESCALATION_ACTIONS = [
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


class cloudtrail_threat_detector_privilege_escalation(Check):
    def execute(self):
        findings = []
        for trail in cloudtrail_client.trails:
            for event_name in PRIVILEGE_ESCALATION_ACTIONS:
                for event_log in cloudtrail_client.__lookup_events__(
                    trail=trail,
                    event_name=event_name,
                    days=THREAT_DETECTION_DAYS,
                ):
                    print(event_log)
                    break
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
