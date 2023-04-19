from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

critical_service = "kms"


class iam_policy_no_full_access_to_kms(Check):
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
                report.status_extended = f"Custom Policy {policy.name} does not allow '{critical_service}:*' privileges"
                if policy.document:
                    # Check the statements, if one includes critical_service:* stop iterating over the rest
                    if type(policy.document.get("Statement")) != list:
                        policy_statements = [policy.document.get("Statement")]
                    else:
                        policy_statements = policy.document.get("Statement")
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
                            report.status_extended = f"Custom Policy {policy.name} allows '{critical_service}:*' privileges"
                            break
                findings.append(report)
        return findings
