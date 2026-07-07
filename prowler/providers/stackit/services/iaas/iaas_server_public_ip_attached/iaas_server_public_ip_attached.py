from prowler.lib.check.models import Check, CheckReportStackIT
from prowler.providers.stackit.services.iaas.iaas_client import iaas_client


class iaas_server_public_ip_attached(Check):
    """
    Check if IaaS servers have public IP addresses directly attached.

    This check verifies that servers do not have a public IP address
    directly attached to their network interfaces, which would expose
    them to inbound traffic from the internet.
    """

    def execute(self):
        """
        Execute the check for all servers in the StackIT project.

        Returns:
            list: A list of CheckReportStackIT findings
        """
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
