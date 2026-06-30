from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.groups.groups_client import (
    groups_client,
)


class groups_view_conversations_restricted(Check):
    """Check that the default permission to view conversations is set to All Group Members.

    This check verifies that the domain-level Groups for Business policy
    restricts conversation viewing to group members only, preventing
    broader access by all organization users or anyone.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if groups_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=groups_client.policies,
                resource_id="groupsPolicies",
                resource_name="Groups Policies",
                customer_id=groups_client.provider.identity.customer_id,
            )

            view_access = groups_client.policies.view_topics_default_access_level
            domain = groups_client.provider.identity.domain

            if view_access == "GROUP_MEMBERS":
                report.status = "PASS"
                report.status_extended = (
                    f"Default permission to view conversations is set to "
                    f"all group members in domain {domain}."
                )
            elif view_access is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Default permission to view conversations uses Google's default "
                    f"configuration (all organization users) in domain {domain}. "
                    f"It should be restricted to all group members only."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Default permission to view conversations is set to "
                    f"{view_access} in domain {domain}. "
                    f"It should be restricted to all group members only."
                )

            findings.append(report)

        return findings
