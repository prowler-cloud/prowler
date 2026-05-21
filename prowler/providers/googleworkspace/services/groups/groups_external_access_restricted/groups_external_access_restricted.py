from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.groups.groups_client import (
    groups_client,
)


class groups_external_access_restricted(Check):
    """Check that accessing groups from outside the organization is set to private.

    This check verifies that the domain-level Groups for Business policy
    restricts external access so that only domain users can view groups,
    preventing information exposure to external parties.
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

            collaboration = groups_client.policies.collaboration_capability
            domain = groups_client.provider.identity.domain

            if collaboration == "DOMAIN_USERS_ONLY":
                report.status = "PASS"
                report.status_extended = (
                    f"Groups external access is set to private (domain users only) "
                    f"in domain {domain}."
                )
            elif collaboration is None:
                report.status = "PASS"
                report.status_extended = (
                    f"Groups external access uses Google's secure default "
                    f"configuration (private) in domain {domain}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Groups external access is set to {collaboration} "
                    f"in domain {domain}. "
                    f"External access should be set to private (domain users only)."
                )

            findings.append(report)

        return findings
