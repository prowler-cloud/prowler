from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.containerregistry.containerregistry_client import (
    containerregistry_client,
)


class containerregistry_not_publicly_accessible(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription, registries in containerregistry_client.registries.items():
            for registry_id, container_registry_info in registries.items():
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = container_registry_info.name
                report.resource_id = registry_id
                report.location = container_registry_info.location
                report.status = "FAIL"
                report.status_extended = f"Container Registry {container_registry_info.name} from subscription {subscription} allows unrestricted network access."

                if not container_registry_info.public_network_access:
                    report.status = "PASS"
                    report.status_extended = f"Container Registry {container_registry_info.name} from subscription {subscription} does not allow unrestricted network access."

                findings.append(report)

        return findings
