from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.networkfirewall.networkfirewall_client import (
    networkfirewall_client,
)


class networkfirewall_deletion_protection(Check):
    def execute(self):
        findings = []
        for firewall in networkfirewall_client.network_firewalls.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=firewall
            )
            report.status = "FAIL"
            report.status_extended = f"Network Firewall {firewall.name} does not have deletion protection enabled."
            if firewall.deletion_protection:
                report.status = "PASS"
                report.status_extended = (
                    f"Network Firewall {firewall.name} has deletion protection enabled."
                )

            findings.append(report)

        return findings
