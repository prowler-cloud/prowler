from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.containerregistry.containerregistry_client import (
    containerregistry_client,
)


class containerregistry_network_access_restricted(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription, registries in containerregistry_client.registries.items():
            for registry_id, ContainerRegistryInfo in registries.items():
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = ContainerRegistryInfo.name
                report.resource_id = registry_id
                report.location = ContainerRegistryInfo.location
                report.status = "FAIL"
                report.status_extended = f"Container Registry {ContainerRegistryInfo.name} from subscription {subscription} allows unrestricted network access."

                if (
                    ContainerRegistryInfo.network_rule_set.default_action.lower()
                    == "deny"
                ):
                    report.status = "PASS"
                    report.status_extended = f"Container Registry {ContainerRegistryInfo.name} from subscription {subscription} does not allow unrestricted network access."

                findings.append(report)

        return findings
