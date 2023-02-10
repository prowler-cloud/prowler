from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_policy_no_administrative_privileges(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for policy in iam_client.policies:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_arn = policy["Arn"]
            report.resource_id = policy["PolicyName"]
            report.status = "PASS"
            report.status_extended = f"Policy {policy['PolicyName']} does not allow '*:*' administrative privileges"
            if policy.get("PolicyDocument"):
                # Check the statements, if one includes *:* stop iterating over the rest
                if type(policy["PolicyDocument"]["Statement"]) != list:
                    policy_statements = [policy["PolicyDocument"]["Statement"]]
                else:
                    policy_statements = policy["PolicyDocument"]["Statement"]
                for statement in policy_statements:
                    # Check policies with "Effect": "Allow" with "Action": "*" over "Resource": "*".
                    if (
                        statement["Effect"] == "Allow"
                        and "Action" in statement
                        and (statement["Action"] == "*" or statement["Action"] == ["*"])
                        and (
                            statement["Resource"] == "*"
                            or statement["Resource"] == ["*"]
                        )
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"Policy {policy['PolicyName']} allows '*:*' administrative privileges"
                        break
            findings.append(report)
        return findings
