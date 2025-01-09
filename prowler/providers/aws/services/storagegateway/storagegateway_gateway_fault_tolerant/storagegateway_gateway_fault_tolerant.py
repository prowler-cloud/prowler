from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.storagegateway.storagegateway_client import (
    storagegateway_client,
)


class storagegateway_gateway_fault_tolerant(Check):
    def execute(self):
        findings = []
        for gateway in storagegateway_client.gateways:
            report = Check_Report_AWS(self.metadata())
            report.region = gateway.region
            report.resource_id = gateway.id
            report.resource_arn = gateway.arn
            report.status = "FAIL"
            report.status_extended = f"StorageGateway Gateway {gateway.name} may not be fault tolerant as it is hosted on {gateway.environment}."
            if gateway.environment != "EC2":
                report.status = "PASS"
                report.status_extended = f"StorageGateway Gateway {gateway.name} may be fault tolerant as it is hosted on {gateway.environment}."

            findings.append(report)

        return findings
