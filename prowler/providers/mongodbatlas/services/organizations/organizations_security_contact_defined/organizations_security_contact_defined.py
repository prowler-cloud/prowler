from typing import List

from prowler.lib.check.models import Check, CheckReportMongoDBAtlas
from prowler.providers.mongodbatlas.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_security_contact_defined(Check):
    """Check if organization has a Security Contact defined

    This class verifies that MongoDB Atlas organizations have a security contact
    defined to receive security-related notifications.
    """

    def execute(self) -> List[CheckReportMongoDBAtlas]:
        """Execute the MongoDB Atlas organization security contact defined check

        Iterates over all organizations and checks if they have a security contact
        defined to receive security-related notifications.

        Returns:
            List[CheckReportMongoDBAtlas]: A list of reports for each organization
        """
        findings = []

        for organization in organizations_client.organizations.values():
            report = CheckReportMongoDBAtlas(
                metadata=self.metadata(), resource=organization
            )

            if organization.settings.security_contact:
                report.status = "PASS"
                report.status_extended = (
                    f"Organization {organization.name} has a security contact defined: "
                    f"{organization.settings.security_contact}"
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Organization {organization.name} does not have a security contact "
                    f"defined to receive security-related notifications."
                )

            findings.append(report)

        return findings
