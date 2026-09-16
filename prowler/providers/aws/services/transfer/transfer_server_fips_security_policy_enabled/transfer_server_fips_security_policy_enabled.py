from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.transfer.transfer_client import transfer_client


class transfer_server_fips_security_policy_enabled(Check):
    """Ensure every AWS Transfer Family server uses a FIPS security policy."""

    def execute(self) -> list[Check_Report_AWS]:
        """Report whether each Transfer Family server uses a FIPS security policy."""
        findings = []
        unretrieved_servers = []
        for server in transfer_client.servers.values():
            policy = server.security_policy_name
            if not policy:
                unretrieved_servers.append(server.id)
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=server)
            if "FIPS" in policy.split("-"):
                report.status = "PASS"
                report.status_extended = (
                    f"Transfer Server {server.id} uses FIPS security policy {policy}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Transfer Server {server.id} uses security policy {policy}, which is not a FIPS security policy."
            findings.append(report)
        if unretrieved_servers:
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.resource_id = transfer_client.audited_account
            report.resource_arn = transfer_client.audited_account_arn
            report.region = transfer_client.region
            report.status = "MANUAL"
            report.status_extended = (
                "Transfer Server security policies could not be retrieved for "
                f"{', '.join(unretrieved_servers)}; verify the transfer:DescribeServer permission."
            )
            findings.append(report)
        return findings
