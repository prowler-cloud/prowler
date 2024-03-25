import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)

ENTROPY_THRESHOLD = cloudtrail_client.audit_config.get("threat_detection_entropy", 0.7)
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
        potential_privilege_escalation = {}
        found_potential_privilege_escalation = False
        for trail in cloudtrail_client.trails:
            for event_name in PRIVILEGE_ESCALATION_ACTIONS:
                for event_log in cloudtrail_client.__lookup_events__(
                    trail=trail,
                    event_name=event_name,
                    days=THREAT_DETECTION_DAYS,
                ):
                    event_log = json.loads(event_log["CloudTrailEvent"])
                    if ".amazonaws.com" not in event_log["sourceIPAddress"]:
                        if (
                            event_log["sourceIPAddress"]
                            not in potential_privilege_escalation
                        ):
                            potential_privilege_escalation[
                                event_log["sourceIPAddress"]
                            ] = set()
                        potential_privilege_escalation[
                            event_log["sourceIPAddress"]
                        ].add(event_name)
        for source_ip, actions in potential_privilege_escalation.items():
            if len(actions) / len(PRIVILEGE_ESCALATION_ACTIONS) > ENTROPY_THRESHOLD:
                found_potential_privilege_escalation = True
                report = Check_Report_AWS(self.metadata())
                report.region = trail.region
                report.resource_id = trail.name
                report.resource_arn = trail.arn
                report.resource_tags = trail.tags
                report.status = "FAIL"
                report.status_extended = f"Potential privilege escalation detected from source IP {source_ip} with an entropy of {ENTROPY_THRESHOLD}."
                findings.append(report)
        if not found_potential_privilege_escalation:
            report = Check_Report_AWS(self.metadata())
            report.region = trail.region
            report.resource_id = trail.name
            report.resource_arn = trail.arn
            report.resource_tags = trail.tags
            report.status = "PASS"
            report.status_extended = "No potential privilege escalation detected."
            findings.append(report)
        return findings
