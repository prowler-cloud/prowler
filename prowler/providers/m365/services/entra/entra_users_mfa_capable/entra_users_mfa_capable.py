from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_users_mfa_capable(Check):
    """
    Ensure all member users are MFA capable.

    This check verifies if member users are MFA capable, aligning with CIS
    Microsoft 365 Foundations Benchmark recommendation 5.2.3.4
    ("Ensure all member users are 'MFA capable'").

    Guest users and disabled accounts are excluded from the evaluation.

    - PASS: The member user is MFA capable.
    - FAIL: The member user is not MFA capable, or MFA capability cannot be
      verified due to insufficient permissions to read user registration details.
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the MFA capable check for all enabled member users.

        Iterates over the users retrieved from the Entra client and generates a report
        indicating if member users are MFA capable. Users explicitly typed as ``Guest``
        and disabled accounts are skipped, in line with the CIS recommendation that
        scopes the control to member users only. Users whose ``user_type`` could not
        be determined are still evaluated to avoid silently dropping accounts when
        Microsoft Graph does not return the property.

        Returns:
            List[CheckReportM365]: A list with one report per evaluated user.
        """
        findings = []

        # Check if there was an error retrieving user registration details
        if entra_client.user_registration_details_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="User Registration Details",
                resource_id="userRegistrationDetails",
            )
            report.status = "FAIL"
            report.status_extended = f"Cannot verify MFA capability for users: {entra_client.user_registration_details_error}."
            findings.append(report)
            return findings

        for user in entra_client.users.values():
            if user.user_type == "Guest" or not user.account_enabled:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=user,
                resource_name=user.name,
                resource_id=user.id,
            )

            if not user.is_mfa_capable:
                report.status = "FAIL"
                report.status_extended = f"User {user.name} is not MFA capable."
            else:
                report.status = "PASS"
                report.status_extended = f"User {user.name} is MFA capable."

            findings.append(report)

        return findings
