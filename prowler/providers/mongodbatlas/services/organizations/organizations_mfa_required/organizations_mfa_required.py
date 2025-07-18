from typing import List

from prowler.lib.check.models import Check, CheckReportMongoDBAtlas
from prowler.providers.mongodbatlas.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_mfa_required(Check):
    """Check if organization requires MFA

    This class verifies that MongoDB Atlas organizations require users
    to set up Multi-Factor Authentication (MFA) before accessing the organization.
    """

    def execute(self) -> List[CheckReportMongoDBAtlas]:
        """Execute the MongoDB Atlas organization MFA required check

        Iterates over all organizations and checks if they require users
        to set up Multi-Factor Authentication (MFA) before accessing the organization.

        Returns:
            List[CheckReportMongoDBAtlas]: A list of reports for each organization
        """
        findings = []

        for organization in organizations_client.organizations.values():
            report = CheckReportMongoDBAtlas(
                metadata=self.metadata(), resource=organization
            )

            mfa_required = organization.settings.get("multiFactorAuthRequired", False)

            if mfa_required:
                report.status = "PASS"
                report.status_extended = (
                    f"Organization {organization.name} requires users to set up "
                    f"Multi-Factor Authentication (MFA) before accessing the organization."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Organization {organization.name} does not require users to set up "
                    f"Multi-Factor Authentication (MFA) before accessing the organization."
                )

            findings.append(report)

        return findings
