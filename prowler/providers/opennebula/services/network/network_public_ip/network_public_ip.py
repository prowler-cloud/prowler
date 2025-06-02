from prowler.lib.logger import logger
from prowler.lib.check.models import Check, Check_Report_OpenNebula
from prowler.providers.opennebula.services.network.network_client import network_client

class network_public_ip(Check):
    def execute(self):
        findings = []
        logger.info("Checking for VNets using public IP addresses...")
        for vnet in network_client.vnets:
            report = Check_Report_OpenNebula(
                metadata=self.metadata(),
                resource=vnet,
            )
            if vnet.public_ips:
                report.status = "FAIL"
                report.status_extended = (
                    f"VNet '{vnet.name}' (ID: {vnet.id}) uses public IP addresses."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"VNet '{vnet.name}' (ID: {vnet.id}) does not use public IP addresses."
                )
            findings.append(report)
        return findings
