from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.search.search_client import search_client
form typing import List

class aisearch_service_not_publicly_accessible(Check):
    def execute(self) -> List[Check_Report_Azure]:
        findings = []

        for subscription, search_services in search_client.search_services.items():
            for search_service_info in search_services:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = search_service_info.name
                report.resource_id = search_service_info.id
                report.location = search_service_info.location
                report.status = "FAIL"
                report.status_extended = f"Search Service {search_service_info.name} from subscription {subscription} allows public access."

                if not search_service_info.public_network_access:
                    report.status = "PASS"
                    report.status_extended = f"Search Service {search_service_info.name} from subscription {subscription} does not allows public access."

                findings.append(report)

        return findings
