from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

critical_service = "cloudtrail"


class iam_policy_no_full_access_to_cloudtrail(Check):
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
                    if not isinstance(policy.document["Statement"], list):
                        policy_statements = [policy.document["Statement"]]
                    else:
                        policy_statements = policy.document["Statement"]
                    # Check the statements, if one includes kms:* stop iterating over the rest
                    for statement in policy_statements:
                        if (
                            statement["Effect"] == "Allow"
                            and "Action" in statement
                            and critical_service + ":*" in statement["Action"]
                            and (
                                statement["Resource"] == "*"
                                or statement["Resource"] == ["*"]
                            )
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"Custom Policy {policy.name} allows '{critical_service}:*' privileges"
                            break
                findings.append(report)
        return findings
