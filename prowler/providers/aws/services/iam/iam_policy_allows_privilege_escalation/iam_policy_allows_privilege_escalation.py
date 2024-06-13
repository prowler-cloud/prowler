from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.privilege_escalation import (
    check_privilege_escalation,
)

# Does the tool analyze both users and roles, or just one or the other? --> Everything using AttachementCount.
# Does the tool take a principal-centric or policy-centric approach? --> Policy-centric approach.
# Does the tool handle resource constraints? --> We don't check if the policy affects all resources or not, we check everything.
# Does the tool consider the permissions of service roles? --> Just checks policies.
# Does the tool handle transitive privesc paths (i.e., attack chains)? --> Not yet.
# Does the tool handle the DENY effect as expected? --> Yes, it checks DENY's statements with Action and NotAction.
# Does the tool handle NotAction as expected? --> Yes
# Does the tool handle Condition constraints? --> Not yet.
# Does the tool handle service control policy (SCP) restrictions? --> No, SCP are within Organizations AWS API.

# Based on:
# - https://bishopfox.com/blog/privilege-escalation-in-aws
# - https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/aws-pentest-tools/aws_escalate.py
# - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/


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

                policies_affected = check_privilege_escalation(policy)

                if policies_affected:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Custom Policy {report.resource_arn} allows privilege escalation using the following actions: {policies_affected}".rstrip()
                        + "."
                    )

                findings.append(report)

        return findings
