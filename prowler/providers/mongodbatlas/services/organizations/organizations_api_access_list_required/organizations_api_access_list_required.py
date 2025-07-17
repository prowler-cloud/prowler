from typing import List

from prowler.lib.check.models import Check, CheckReportMongoDBAtlas
from prowler.providers.mongodbatlas.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_api_access_list_required(Check):
    """Check if organization requires API access list

    This class verifies that MongoDB Atlas organizations require API operations
    to originate from an IP Address added to the API access list.
    """

    def execute(self) -> List[CheckReportMongoDBAtlas]:
        """Execute the MongoDB Atlas organization API access list required check

        Iterates over all organizations and checks if they require API operations
        to originate from an IP Address added to the API access list.

        Returns:
            List[CheckReportMongoDBAtlas]: A list of reports for each organization
        """
        findings = []

        for organization in organizations_client.organizations.values():
            report = CheckReportMongoDBAtlas(
                metadata=self.metadata(), resource=organization
            )

            api_access_list_required = organization.settings.get(
                "apiAccessListRequired", False
            )

            if api_access_list_required:
                report.status = "PASS"
                report.status_extended = (
                    f"Organization {organization.name} requires API operations "
                    f"to originate from an IP Address added to the API access list."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Organization {organization.name} does not require API operations "
                    f"to originate from an IP Address added to the API access list."
                )

            findings.append(report)

        return findings
