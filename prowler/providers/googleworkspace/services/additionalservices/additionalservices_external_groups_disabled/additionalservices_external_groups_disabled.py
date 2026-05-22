from typing import List

from prowler.lib.check.models import Check, CheckReportGoogleWorkspace
from prowler.providers.googleworkspace.services.additionalservices.additionalservices_client import (
    additionalservices_client,
)


class additionalservices_external_groups_disabled(Check):
    """Check that access to external Google Groups is disabled for all users.

    This check verifies that the domain-level Additional Google services policy
    disables external Google Groups access, preventing users from accessing
    groups created outside the organization.
    """

    def execute(self) -> List[CheckReportGoogleWorkspace]:
        findings = []

        if additionalservices_client.policies_fetched:
            report = CheckReportGoogleWorkspace(
                metadata=self.metadata(),
                resource=additionalservices_client.policies,
                resource_id="additionalServicesPolicies",
                resource_name="Additional Services Policies",
                customer_id=additionalservices_client.provider.identity.customer_id,
            )

            groups_state = additionalservices_client.policies.groups_service_state

            if groups_state == "DISABLED":
                report.status = "PASS"
                report.status_extended = (
                    f"Access to external Google Groups is disabled "
                    f"in domain {additionalservices_client.provider.identity.domain}."
                )
            else:
                report.status = "FAIL"
                if groups_state is None:
                    report.status_extended = (
                        f"Access to external Google Groups is not explicitly configured "
                        f"in domain {additionalservices_client.provider.identity.domain}. "
                        f"The default is ON for everyone. "
                        f"External Google Groups access should be disabled."
                    )
                else:
                    report.status_extended = (
                        f"Access to external Google Groups is enabled "
                        f"in domain {additionalservices_client.provider.identity.domain}. "
                        f"External Google Groups access should be disabled."
                    )

            findings.append(report)

        return findings
