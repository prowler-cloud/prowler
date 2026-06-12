from prowler.lib.check.models import Check, CheckReportStackIT
from prowler.providers.stackit.services.iaas.iaas_client import iaas_client


class iaas_server_public_ip_attached(Check):
    def execute(self):
        findings = []

        for server in iaas_client.servers:
            report = CheckReportStackIT(
                metadata=self.metadata(),
                resource=server,
            )

            if server.has_public_ip:
                report.status = "FAIL"
                report.status_extended = (
                    f"Server {server.name} has a public IP address directly attached, "
                    f"exposing it to the internet."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Server {server.name} does not have a public IP address attached."
                )

            findings.append(report)

        return findings
