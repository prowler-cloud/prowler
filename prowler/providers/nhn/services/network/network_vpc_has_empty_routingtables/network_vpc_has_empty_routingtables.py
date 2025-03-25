from prowler.lib.check.models import Check, CheckReportNHN
from prowler.providers.nhn.services.network.network_client import network_client


class network_vpc_has_empty_routingtables(Check):
    def execute(self):
        findings = []
        for network in network_client.networks:
            report = CheckReportNHN(
                metadata=self.metadata(),
                resource=network,
                resource_name=network.name,
                resource_id=network.id,
                resource_location="kr1",
            )
            report.status = "PASS"
            report.status_extended = (
                f"VPC {network.name} does not have empty routingtables."
            )
            if network.empty_routingtables:
                report.status = "FAIL"
                report.status_extended = f"VPC {network.name} has empty routingtables."
            findings.append(report)

        return findings
