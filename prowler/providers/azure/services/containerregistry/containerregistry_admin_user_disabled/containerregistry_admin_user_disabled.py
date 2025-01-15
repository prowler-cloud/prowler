from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.containerregistry.containerregistry_client import (
    containerregistry_client,
)


class containerregistry_admin_user_disabled(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription, registries in containerregistry_client.registries.items():
            for container_registry_info in registries.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource_metadata=container_registry_info
                )
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"Container Registry {container_registry_info.name} from subscription {subscription} has its admin user enabled."

                if not container_registry_info.admin_user_enabled:
                    report.status = "PASS"
                    report.status_extended = f"Container Registry {container_registry_info.name} from subscription {subscription} has its admin user disabled."

                findings.append(report)

        return findings
