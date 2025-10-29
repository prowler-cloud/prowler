from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_settings_password_never_expire(Check):
    """Check if the tenant enforces a 'Password never expires' policy.

    This check verifies whether the tenant-wide password policy (surfaced through the first
    domain returned by Microsoft 365) is set to never expire. If the password validity period
    is set to `2147483647`, the policy is considered to have 'password never expires'.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for password never expires policy.

        This method inspects the tenant-level password validity configuration (exposed through
        the first available domain) and checks if the password validity period is set to
        `2147483647`, indicating that passwords for users in the domain never expire.

        Returns:
            List[CheckReportM365]: A list of reports indicating whether the domain's password
            policy is set to never expire.
        """
        findings = []
        password_policy = getattr(admincenter_client, "password_policy", None)
        if password_policy:
            report = CheckReportM365(
                self.metadata(),
                resource=password_policy,
                resource_name="Password Policy",
                resource_id="passwordPolicy",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Tenant Password policy does not have a Password never expires policy."
            )

            if password_policy.password_validity_period == 2147483647:
                report.status = "PASS"
                report.status_extended = (
                    "Tenant Password policy is set to never expire."
                )

            findings.append(report)

        return findings
