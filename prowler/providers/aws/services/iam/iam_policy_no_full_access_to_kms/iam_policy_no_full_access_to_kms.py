from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

critical_service = "kms"

class iam_policy_no_full_access_to_kms(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for policy in iam_client.policies:
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_arn = policy.get("Arn")
            report.resource_id = policy.get("PolicyName")
            report.status = "PASS"
            report.status_extended = f"Policy {policy.get('PolicyName')} does not allow '{critical_service}:*' privileges"
            if policy.get("PolicyDocument"):
                # Check the statements, if one includes critical_service:* stop iterating over the rest
                if type(policy.get("PolicyDocument").get("Statement")) != list:
                    policy_statements = [policy.get("PolicyDocument").get("Statement")]
                else:
                    policy_statements = policy.get("PolicyDocument").get("Statement")
                for statement in policy_statements:
                    # Check policies with "Effect": "Allow" with "Action": "*" over "Resource": "*".
                    if (
                        statement.get("Effect") == "Allow"
                        and critical_service + ":*" in statement.get("Action")
                        and (
                            statement.get("Resource") == "*"
                            or statement.get("Resource") == ["*"]
                        )
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"Policy {policy.get('PolicyName')} allows '{critical_service}:*' privileges"
                        break
            findings.append(report)
        return findings
