from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class iam_role_cross_service_confused_deputy_prevention(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        if iam_client.roles:
            for role in iam_client.roles:
                # This check should only be performed against service roles (avoid Service Linked Roles since the trust relationship cannot be changed)
                if role.is_service_role and "aws-service-role" not in role.arn:
                    report = Check_Report_AWS(self.metadata())
                    report.region = iam_client.region
                    report.resource_arn = role.arn
                    report.resource_id = role.name
                    report.resource_tags = role.tags
                    report.status = "FAIL"
                    report.status_extended = f"IAM Service Role {role.name} does not prevent against a cross-service confused deputy attack."
                    if not is_policy_public(
                        role.assume_role_policy,
                        iam_client.audited_account,
                        check_cross_service_confused_deputy=True,
                        not_allowed_actions=["sts:AssumeRole", "sts:*"],
                    ):
                        report.status = "PASS"
                        report.status_extended = f"IAM Service Role {role.name} prevents against a cross-service confused deputy attack."

                    findings.append(report)

        return findings
