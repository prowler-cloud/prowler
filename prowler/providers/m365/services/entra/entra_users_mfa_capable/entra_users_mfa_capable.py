from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_users_mfa_capable(Check):
    """
    Ensure all users are MFA capable.

    This check verifies if users are MFA capable.

    - PASS: The user is MFA capable.
    - FAIL: The user is not MFA capable, or MFA capability cannot be verified
      due to insufficient permissions to read user registration details.
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the admin MFA capable check for all users.

        Iterates over the users retrieved from the Entra client and generates a report
        indicating if users are MFA capable.

        Returns:
            List[CheckReportM365]: A list containing a single report with the result of the check.
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
            if user.account_enabled:
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
