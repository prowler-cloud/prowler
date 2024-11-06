from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dms.dms_client import dms_client


class dms_endpoint_redis_in_transit_encryption_enabled(Check):
    """
    Check if AWS DMS Endpoints for Redis OSS have TLS enabled.

    This class verifies whether each AWS DMS Endpoint configured for Redis OSS is encrypted in transit
    by checking the `TlsEnabled` property in the endpoint's configuration. The check ensures that
    TLS is enabled to secure data in transit, preventing unauthorized access and ensuring data integrity.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """
        Execute the DMS Redis TLS enabled check.

        Iterates over all DMS Endpoints and generates a report indicating whether
        each Redis OSS endpoint is encrypted in transit.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
        findings = []
        for endpoint_arn, endpoint in dms_client.endpoints.items():
            if endpoint.engine_name == "redis":
                report = Check_Report_AWS(self.metadata())
                report.resource_id = endpoint.id
                report.resource_arn = endpoint_arn
                report.region = endpoint.region
                report.resource_tags = endpoint.tags
                report.status = "FAIL"
                report.status_extended = f"DMS Endpoint {endpoint.id} for Redis OSS is not encrypted in transit."
                if endpoint.redis_ssl_protocol == "ssl-encryption":
                    report.status = "PASS"
                    report.status_extended = f"DMS Endpoint {endpoint.id} for Redis OSS is encrypted in transit."

                findings.append(report)

        return findings
