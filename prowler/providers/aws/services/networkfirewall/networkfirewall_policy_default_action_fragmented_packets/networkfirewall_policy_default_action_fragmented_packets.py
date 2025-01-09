from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.networkfirewall.networkfirewall_client import (
    networkfirewall_client,
)


class networkfirewall_policy_default_action_fragmented_packets(Check):
    def execute(self):
        findings = []
        for arn, firewall in networkfirewall_client.network_firewalls.items():
            report = Check_Report_AWS(self.metadata())
            report.region = firewall.region
            report.resource_id = firewall.name
            report.resource_arn = arn
            report.resource_tags = firewall.tags
            report.status = "FAIL"
            report.status_extended = f"Network Firewall {firewall.name} policy does not drop or forward fragmented packets by default."

            if (
                "aws:drop" in firewall.default_stateless_frag_actions
                or "aws:forward_to_sfe" in firewall.default_stateless_frag_actions
            ):
                report.status = "PASS"
                report.status_extended = f"Network Firewall {firewall.name} policy does drop or forward fragmented packets by default."

            findings.append(report)

        return findings
