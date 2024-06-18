from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.privilege_escalation import (
    check_privilege_escalation,
)


class iam_policy_allows_privilege_escalation(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for policy in iam_client.policies:
            if policy.type == "Custom":
                report = Check_Report_AWS(self.metadata())
                report.resource_id = policy.name
                report.resource_arn = policy.arn
                report.region = iam_client.region
                report.resource_tags = policy.tags
                report.status = "PASS"
                report.status_extended = f"Custom Policy {report.resource_arn} does not allow privilege escalation."

                policies_affected = check_privilege_escalation(
                    getattr(policy, "document", {})
                )

                if policies_affected:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Custom Policy {report.resource_arn} allows privilege escalation using the following actions: {policies_affected}".rstrip()
                        + "."
                    )

                findings.append(report)

        return findings
