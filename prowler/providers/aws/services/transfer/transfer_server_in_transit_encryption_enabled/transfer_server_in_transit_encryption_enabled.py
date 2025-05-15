from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.transfer.transfer_client import transfer_client
from prowler.providers.aws.services.transfer.transfer_service import Protocol


class transfer_server_in_transit_encryption_enabled(Check):
    """Check if Transfer Servers have encryption in transit enabled.

    This class checks if Transfer Servers have encryption in transit enabled.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the server in transit encyption check.

        Iterate over all Transfer Servers and check if they have FTP as one of the valid protocols.

        Returns:
            List[Check_Report_AWS]: A list of reports for each Transfer Server.
        """
        findings = []
        for server in transfer_client.servers.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=server)
            report.status = "PASS"
            report.status_extended = (
                f"Transfer Server {server.id} does have encryption in transit enabled."
            )

            if Protocol.FTP in server.protocols:
                report.status = "FAIL"
                report.status_extended = f"Transfer Server {server.id} does not have encryption in transit enabled."

            findings.append(report)

        return findings
