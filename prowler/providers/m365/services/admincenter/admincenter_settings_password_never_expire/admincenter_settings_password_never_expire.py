from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_settings_password_never_expire(Check):
    """Check if domains have a 'Password never expires' policy.

    This check verifies whether the password policy for each domain is set to never expire.
    If the domain password validity period is set to `2147483647`, the policy is considered to
    have 'password never expires'.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for password never expires policy.

        This method iterates over all domains and checks if the password validity period is set
        to `2147483647`, indicating that passwords for users in the domain never expire.

        Returns:
            List[CheckReportM365]: A list of reports indicating whether the domain's password
            policy is set to never expire.
        """
        findings = []
        for domain in admincenter_client.domains.values():
            report = CheckReportM365(
                self.metadata(),
                resource=domain,
                resource_name=domain.id,
                resource_id=domain.id,
            )
            report.status = "FAIL"
            report.status_extended = (
                f"Domain {domain.id} does not have a Password never expires policy."
            )

            if domain.password_validity_period == 2147483647:
                report.status = "PASS"
                report.status_extended = (
                    f"Domain {domain.id} Password policy is set to never expire."
                )

            findings.append(report)

        return findings
