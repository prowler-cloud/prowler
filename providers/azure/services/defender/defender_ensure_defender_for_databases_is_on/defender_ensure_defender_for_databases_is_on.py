from lib.check.models import Check, Check_Report
from providers.azure.services.defender.defender_client import defender_client


class defender_ensure_defender_for_databases_is_on(Check):
    def execute(self) -> Check_Report:
        findings = []
        for subscription, defender_plan in defender_client.pricings.items():
            report = Check_Report(self.metadata)
            report.region = defender_client.region
            report.status = "PASS"
            report.resource_id = "Defender plan Databases"
            report.status_extended = f"Defender plan Defender for Databases from subscription {subscription} is set to ON (pricing tier standard)"
            if (
                (
                    defender_plan.name == "SqlServers"
                    and defender_plan.pricing_tier != "Standard"
                )
                or (
                    defender_plan.name == "SqlServerVirtualMachines"
                    and defender_plan.pricing_tier != "Standard"
                )
                or (
                    defender_plan.name == "OpenSourceRelationalDatabases"
                    and defender_plan.pricing_tier != "Standard"
                )
                or (
                    defender_plan.name == "CosmosDbs"
                    and defender_plan.pricing_tier != "Standard"
                )
            ):
                report.status = "FAIL"
                report.status_extended = f"Defender plan Defender for Databases from subscription {subscription} is set to OFF (pricing tier not standard)"

            findings.append(report)
        return findings
