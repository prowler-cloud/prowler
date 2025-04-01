from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client


class defender_ensure_defender_for_azure_sql_databases_is_on(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, pricings in defender_client.pricings.items():
            if "SqlServers" in pricings:
<<<<<<< HEAD
                report = Check_Report_Azure(self.metadata())
=======
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=pricings["SqlServers"]
                )
                report.subscription = subscription
>>>>>>> 5a59bb335 (fix(resources): add the correct id and names for resources (#7410))
                report.status = "PASS"
                report.subscription = subscription
                report.resource_id = pricings["SqlServers"].resource_id
                report.resource_name = "Defender plan Azure SQL DB Servers"
                report.status_extended = f"Defender plan Defender for Azure SQL DB Servers from subscription {subscription} is set to ON (pricing tier standard)."
                if pricings["SqlServers"].pricing_tier != "Standard":
                    report.status = "FAIL"
                    report.status_extended = f"Defender plan Defender for Azure SQL DB Servers from subscription {subscription} is set to OFF (pricing tier not standard)."

                findings.append(report)
        return findings
