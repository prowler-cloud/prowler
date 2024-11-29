from typing import List

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aisearch.aisearch_client import aisearch_client


class aisearch_service_not_publicly_accessible(Check):
    def execute(self) -> List[Check_Report_Azure]:
        findings = []

        for (
            subscription_name,
            aisearch_services,
        ) in aisearch_client.aisearch_services.items():
            for aisearch_service_id, aisearch_service in aisearch_services.items():
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription_name
                report.resource_name = aisearch_service.name
                report.resource_id = aisearch_service_id
                report.location = aisearch_service.location
                report.status = "FAIL"
                report.status_extended = f"AISearch Service {aisearch_service.name} from subscription {subscription_name} allows public access."

                if not aisearch_service.public_network_access:
                    report.status = "PASS"
                    report.status_extended = f"AISearch Service {aisearch_service.name} from subscription {subscription_name} does not allows public access."

                findings.append(report)

        return findings
