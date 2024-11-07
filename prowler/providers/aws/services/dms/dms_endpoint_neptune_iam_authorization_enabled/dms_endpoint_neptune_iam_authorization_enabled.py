from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dms.dms_client import dms_client


class dms_endpoint_neptune_iam_authorization_enabled(Check):
    """
    Check if AWS DMS Endpoints for Neptune have IAM authorization enabled.

    This class verifies whether each AWS DMS Endpoint configured for Neptune has IAM authorization enabled
    by checking the `NeptuneSettings.IamAuthEnabled` property in the endpoint's configuration.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """
        Execute the DMS Neptune IAM authorization enabled check.

        Iterates over all DMS Endpoints and generates a report indicating whether
        each Neptune endpoint has IAM authorization enabled.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
        findings = []
        for endpoint_arn, endpoint in dms_client.endpoints.items():
            if endpoint.engine_name == "neptune":
                report = Check_Report_AWS(self.metadata())
                report.resource_id = endpoint.id
                report.resource_arn = endpoint_arn
                report.region = endpoint.region
                report.resource_tags = endpoint.tags
                report.status = "FAIL"
                report.status_extended = f"DMS Endpoint {endpoint.id} for Neptune databases does not have IAM authorization enabled."
                if endpoint.neptune_iam_auth_enabled:
                    report.status = "PASS"
                    report.status_extended = f"DMS Endpoint {endpoint.id} for Neptune databases has IAM authorization enabled."

                findings.append(report)

        return findings
