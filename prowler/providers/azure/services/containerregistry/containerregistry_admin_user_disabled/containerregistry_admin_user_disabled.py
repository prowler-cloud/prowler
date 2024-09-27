from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.containerregistry.containerregistry_client import (
    containerregistry_client,
)


class containerregistry_admin_user_disabled(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription, registries in containerregistry_client.registries.items():
            for registry in registries:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = registry.name
                report.resource_id = registry.id
                report.location = registry.location
                report.status = "FAIL"
                report.status_extended = f"Container Registry {registry.name} from subscription {subscription} has its admin user enabled."

                if registry.admin_user_enabled is False:
                    report.status = "PASS"
                    report.status_extended = f"Container Registry {registry.name} from subscription {subscription} has its admin user disabled."

                findings.append(report)

        return findings
