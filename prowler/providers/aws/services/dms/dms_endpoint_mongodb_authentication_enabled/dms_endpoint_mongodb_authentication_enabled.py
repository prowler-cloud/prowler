from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dms.dms_client import dms_client


class dms_endpoint_mongodb_authentication_enabled(Check):
    """
    Check if AWS DMS Endpoints for MongoDB have an authentication mechanism enabled.

    This class verifies whether each AWS DMS Endpoint configured for MongoDB has an authentication
    mechanism enabled by checking the `AuthType` property in the endpoint's configuration. The check
    ensures that the `AuthType` is not set to "no", indicating that an authentication method is in place.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """
        Execute the DMS MongoDB authentication type configured check.

        Iterates over all DMS Endpoints and generates a report indicating whether
        each MongoDB endpoint has an authentication mechanism enabled.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
        findings = []
        for endpoint_arn, endpoint in dms_client.endpoints.items():
            if endpoint.engine_name == "mongodb":
                report = Check_Report_AWS(self.metadata())
                report.resource_id = endpoint.id
                report.resource_arn = endpoint_arn
                report.region = endpoint.region
                report.resource_tags = endpoint.tags
                report.status = "FAIL"
                report.status_extended = f"DMS Endpoint '{endpoint.id}' for MongoDB does not have an authentication mechanism enabled."
                if endpoint.mongodb_auth_type != "no":
                    report.status = "PASS"
                    report.status_extended = f"DMS Endpoint '{endpoint.id}' for MongoDB has {endpoint.mongodb_auth_type} as the authentication mechanism."

                findings.append(report)

        return findings
