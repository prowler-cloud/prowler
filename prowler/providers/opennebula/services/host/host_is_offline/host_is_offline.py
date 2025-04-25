from prowler.lib.logger import logger
from prowler.lib.check.models import Check, Check_Report_OpenNebula
from prowler.providers.opennebula.services.host.host_client import host_client

class host_is_offline(Check):
    def execute(self):
        findings = []
        logger.info("Checking for OpenNebula hosts that are offline or in error state...")
        for host in host_client.hosts:
            report = Check_Report_OpenNebula(
                metadata=self.metadata(),
                resource=host.name,
            )
            if not host.online:
                report.status = "FAIL"
                report.status_extended = (
                    f"Host {host.name} is not online (state={host.state})."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Host {host.name} is online (state={host.state})."
                )
            findings.append(report)
        return findings
