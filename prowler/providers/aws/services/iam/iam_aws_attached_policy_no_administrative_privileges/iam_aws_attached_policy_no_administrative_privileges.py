from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_aws_attached_policy_no_administrative_privileges(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for policy in iam_client.policies:
            # Check only for attached AWS policies
            if policy.attached and policy.type == "AWS":
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_arn = policy.arn
                report.resource_id = policy.name
                report.resource_tags = policy.tags
                report.status = "PASS"
                report.status_extended = f"{policy.type} policy {policy.name} is attached but does not allow '*:*' administrative privileges."
                if policy.document:
                    # Check the statements, if one includes *:* stop iterating over the rest
                    if not isinstance(policy.document["Statement"], list):
                        policy_statements = [policy.document["Statement"]]
                    else:
                        policy_statements = policy.document["Statement"]
                    for statement in policy_statements:
                        # Check policies with "Effect": "Allow" with "Action": "*" over "Resource": "*".
                        if (
                            statement["Effect"] == "Allow"
                            and "Action" in statement
                            and (
                                statement["Action"] == "*"
                                or statement["Action"] == ["*"]
                            )
                            and (
                                statement["Resource"] == "*"
                                or statement["Resource"] == ["*"]
                            )
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"{policy.type} policy {policy.name} is attached and allows '*:*' administrative privileges."
                            break
                findings.append(report)
        return findings
