from lib.check.models import Check, Check_Report
from providers.azure.services.defender.defender_client import defender_client


class defender_ensure_defender_for_cosmosdb_is_on(Check):
    def execute(self) -> Check_Report:
        findings = []
        report = Check_Report(self.metadata)
        report.region = defender_client.region
        report.status = "PASS"
        report.resource_id = "Defender plan Cosmos DB"
        report.status_extended = (
            "Defender plan Defender for Cosmos DB is set to ON (pricing tier standard)"
        )
        if defender_client.pricings["CosmosDbs"].pricing_tier != "Standard":
            report.status = "FAIL"
            report.status_extended = "Defender plan Defender for Cosmos DB is set to OFF (pricing tier not standard)"

        findings.append(report)
        return findings
