from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_no_custom_policy_permissive_role_assumption(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for policy in iam_client.policies:
            # Check only custom policies
            if policy.type == "Custom":
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_arn = policy.arn
                report.resource_id = policy.name
                report.resource_tags = policy.tags
                report.status = "PASS"
                report.status_extended = f"Custom Policy {policy.name} does not allow permissive STS Role assumption"
                if policy.document:
                    if type(policy.document["Statement"]) != list:
                        policy_statements = [policy.document["Statement"]]
                    else:
                        policy_statements = policy.document["Statement"]
                    for statement in policy_statements:
                        if (
                            statement["Effect"] == "Allow"
                            and "Action" in statement
                            and "Resource" in statement
                            and "*" in statement["Resource"]
                        ):
                            if type(statement["Action"]) == list:
                                for action in statement["Action"]:
                                    if (
                                        action == "sts:AssumeRole"
                                        or action == "sts:*"
                                        or action == "*"
                                    ):
                                        report.status = "FAIL"
                                        report.status_extended = f"Custom Policy {policy.name} allows permissive STS Role assumption"
                                        break
                            else:
                                if (
                                    statement["Action"] == "sts:AssumeRole"
                                    or statement["Action"] == "sts:*"
                                    or statement["Action"] == "*"
                                ):
                                    report.status = "FAIL"
                                    report.status_extended = f"Custom Policy {policy.name} allows permissive STS Role assumption"
                            break

                findings.append(report)

        return findings
