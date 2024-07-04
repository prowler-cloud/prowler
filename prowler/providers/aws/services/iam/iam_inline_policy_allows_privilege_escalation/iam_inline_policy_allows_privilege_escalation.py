from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.privilege_escalation import (
    check_privilege_escalation,
)


class iam_inline_policy_allows_privilege_escalation(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for policy in iam_client.policies:
            if policy.type == "Inline":
                report = Check_Report_AWS(self.metadata())
                report.resource_id = policy.name
                report.resource_arn = policy.arn
                report.region = iam_client.region
                report.resource_tags = policy.tags
                report.status = "PASS"

                if "role" in report.resource_arn:
                    resource_type_str = "role"
                elif "group" in report.resource_arn:
                    resource_type_str = "group"
                elif "user" in report.resource_arn:
                    resource_type_str = "user"
                else:
                    resource_type_str = "resource"

                report.status_extended = f"Inline Policy '{report.resource_id}'{' attached to ' + resource_type_str + ' ' + report.resource_arn if policy.attached else ''} does not allow privilege escalation."

                policies_affected = check_privilege_escalation(
                    getattr(policy, "document", {})
                )

                if policies_affected:
                    report.status = "FAIL"

                    report.status_extended = (
                        f"Inline Policy '{report.resource_id}'{' attached to ' + resource_type_str + ' ' + report.resource_arn if policy.attached else ''} allows privilege escalation using the following actions: {policies_affected}".rstrip()
                        + "."
                    )

                findings.append(report)

        return findings
