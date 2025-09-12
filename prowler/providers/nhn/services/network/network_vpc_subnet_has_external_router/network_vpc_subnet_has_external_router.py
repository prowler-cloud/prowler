from prowler.lib.check.models import Check, CheckReportNHN
from prowler.providers.nhn.services.network.network_client import network_client


class network_vpc_subnet_has_external_router(Check):
    def execute(self):
        findings = []
        for network in network_client.networks:
            for subnet in network.subnets:
                report = CheckReportNHN(
                    metadata=self.metadata(),
                    resource=network,
                )
                report.status = "PASS"
                report.status_extended = f"VPC {network.name} Subnet {subnet.name} does not have an external router."
                if subnet.external_router:
                    report.status = "FAIL"
                    report.status_extended = f"VPC {network.name} Subnet {subnet.name} has an external router."
                findings.append(report)

            return findings
