from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.containerregistry.containerregistry_client import (
    containerregistry_client,
)


class containerregistry_uses_private_link(Check):
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
                report.status_extended = f"Container Registry {container_registry_info.name} from subscription {subscription_name} ({subscription}) does not use a private link."

                if container_registry_info.private_endpoint_connections:
                    report.status = "PASS"
                    report.status_extended = f"Container Registry {container_registry_info.name} from subscription {subscription_name} ({subscription}) uses a private link."

                findings.append(report)

        return findings
