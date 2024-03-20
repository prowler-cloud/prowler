from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)

THREAT_DETECTION_DAYS = cloudtrail_client.audit_config.get("threat_detection_days", 1)
PRIVILEGE_ESCALATION_ACTIONS = [
    "cloudformation:CreateStack",
    "cognito-identity:GetCredentialsForIdentity",
    "cognito-identity:GetId",
    "datapipeline:CreatePipeline",
    "datapipeline:PutPipelineDefinition",
    "ec2:CreateKeyPair",
    "ec2:ModifyInstanceAttribute",
    "ec2:ReplaceIamInstanceProfileAssociation",
    "ec2:RunInstances",
    "eks:AssociateAccessPolicy",
    "eks:CreateAccessEntry",
    "glue:CreateDevEndpoint",
    "glue:CreateJob",
    "glue:UpdateDevEndpoint",
    "glue:UpdateJob",
    "iam:AddRoleToInstanceProfile",
    "iam:AddUserToGroup",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:ChangePassword",
    "iam:CreateAccessKey",
    "iam:CreateGroup",
    "iam:CreateRole",
    "iam:CreateLoginProfile",
    "iam:CreatePolicyVersion",
    "iam:DeleteRolePermissionsBoundary",
    "iam:DeleteRolePolicy",
    "iam:DeleteUserPermissionsBoundary",
    "iam:DeleteUserPolicy",
    "iam:DetachRolePolicy",
    "iam:DetachUserPolicy",
    "iam:GetPolicyVersion",
    "iam:GetUserPolicy",
    "iam:PassRole",
    "iam:PutGroupPolicy",
    "iam:PutRolePermissionsBoundary",
    "iam:PutRolePolicy",
    "iam:PutUserPermissionsBoundary",
    "iam:PutUserPolicy",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "iam:UpdateLoginProfile",
    "lambda:AddPermission",
    "lambda:CreateEventSourceMapping",
    "lambda:CreateFunction",
    "lambda:Invoke",
    "lambda:UpdateEventSourceMapping",
    "lambda:UpdateFunctionCode",
    "sts:AssumeRole",
]


class cloudtrail_threat_detector_privilege_escalation(Check):
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
