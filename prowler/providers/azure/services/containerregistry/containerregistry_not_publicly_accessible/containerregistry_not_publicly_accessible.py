from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.containerregistry.containerregistry_client import (
    containerregistry_client,
)


class containerregistry_not_publicly_accessible(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription, registries in containerregistry_client.registries.items():
            subscription_name = containerregistry_client.subscriptions.get(
                subscription, subscription
            )
            for container_registry_info in registries.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=container_registry_info
                )
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"Container Registry {container_registry_info.name} from subscription {subscription_name} ({subscription}) allows unrestricted network access."

                if not container_registry_info.public_network_access:
                    report.status = "PASS"
                    report.status_extended = f"Container Registry {container_registry_info.name} from subscription {subscription_name} ({subscription}) does not allow unrestricted network access."

                findings.append(report)

        return findings
