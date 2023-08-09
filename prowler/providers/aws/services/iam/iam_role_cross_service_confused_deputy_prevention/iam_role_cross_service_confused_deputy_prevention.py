from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.lib.policy_condition_parser.policy_condition_parser import (
    is_account_only_allowed_in_condition,
)
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_role_cross_service_confused_deputy_prevention(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for role in iam_client.roles:
            # This check should only be performed against service roles (avoid Service Linked Roles since the trust relationship cannot be changed)
            if role.is_service_role and "aws-service-role" not in role.arn:
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_arn = role.arn
                report.resource_id = role.name
                report.resource_tags = role.tags
                report.status = "FAIL"
                report.status_extended = f"IAM Service Role {role.name} does not prevent against a cross-service confused deputy attack"
                for statement in role.assume_role_policy["Statement"]:
                    if (
                        statement["Effect"] == "Allow"
                        and (
                            "sts:AssumeRole" in statement["Action"]
                            or "sts:*" in statement["Action"]
                            or "*" in statement["Action"]
                        )
                        # Need to make sure we are checking the part of the assume role policy document that provides a service access
                        and "Service" in statement["Principal"]
                        # Check to see if the appropriate condition statements have been implemented
                        and "Condition" in statement
                        and is_account_only_allowed_in_condition(
                            statement["Condition"], iam_client.audited_account
                        )
                    ):
                        report.status = "PASS"
                        report.status_extended = f"IAM Service Role {role.name} prevents against a cross-service confused deputy attack"
                        break

                findings.append(report)

        return findings
