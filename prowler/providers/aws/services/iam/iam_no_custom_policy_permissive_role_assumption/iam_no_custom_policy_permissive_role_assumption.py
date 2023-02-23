from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_no_custom_policy_permissive_role_assumption(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for policy in iam_client.policies:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_arn = policy["Arn"]
            report.resource_id = policy["PolicyName"]
            report.status = "PASS"
            report.status_extended = f"Custom Policy {policy['PolicyName']} does not allow permissive STS Role assumption"
            if policy.get("PolicyDocument"):
                if type(policy["PolicyDocument"]["Statement"]) != list:
                    policy_statements = [policy["PolicyDocument"]["Statement"]]
                else:
                    policy_statements = policy["PolicyDocument"]["Statement"]
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
                                    report.status_extended = f"Custom Policy {policy['PolicyName']} allows permissive STS Role assumption"
                                    break
                        else:
                            if (
                                statement["Action"] == "sts:AssumeRole"
                                or statement["Action"] == "sts:*"
                                or statement["Action"] == "*"
                            ):
                                report.status = "FAIL"
                                report.status_extended = f"Custom Policy {policy['PolicyName']} allows permissive STS Role assumption"
                        break

            findings.append(report)

        return findings
