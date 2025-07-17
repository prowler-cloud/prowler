from typing import List

from prowler.lib.check.models import Check, CheckReportMongoDBAtlas
from prowler.providers.mongodbatlas.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_service_account_secrets_expiration(Check):
    """Check if organization has maximum period expiration for Admin API Service Account Secrets

    This class verifies that MongoDB Atlas organizations have a maximum period
    before expiry for new Atlas Admin API Service Account secrets.
    """

    def execute(self) -> List[CheckReportMongoDBAtlas]:
        """Execute the MongoDB Atlas organization service account secrets expiration check

        Iterates over all organizations and checks if they have a maximum period
        expiration for Admin API Service Account secrets set to 8 hours or less.

        Returns:
            List[CheckReportMongoDBAtlas]: A list of reports for each organization
        """
        findings = []

        # Default maximum hours as specified in the ticket (configurable)
        max_hours_threshold = 8

        for organization in organizations_client.organizations.values():
            report = CheckReportMongoDBAtlas(
                metadata=self.metadata(), resource=organization
            )

            max_validity_hours = organization.settings.get(
                "maxServiceAccountSecretValidityInHours"
            )

            if max_validity_hours is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Organization {organization.name} does not have a maximum period "
                    f"expiration configured for Admin API Service Account secrets."
                )
            elif max_validity_hours <= max_hours_threshold:
                report.status = "PASS"
                report.status_extended = (
                    f"Organization {organization.name} has a maximum period expiration "
                    f"of {max_validity_hours} hours for Admin API Service Account secrets, "
                    f"which is within the recommended threshold of {max_hours_threshold} hours."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Organization {organization.name} has a maximum period expiration "
                    f"of {max_validity_hours} hours for Admin API Service Account secrets, "
                    f"which exceeds the recommended threshold of {max_hours_threshold} hours."
                )

            findings.append(report)

        return findings
