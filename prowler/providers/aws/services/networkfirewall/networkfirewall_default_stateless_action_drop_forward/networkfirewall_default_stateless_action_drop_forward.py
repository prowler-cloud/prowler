from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.networkfirewall.networkfirewall_client import (
    networkfirewall_client,
)


class networkfirewall_default_stateless_action_drop_forward(Check):
    def execute(self):
        findings = []
        for arn, firewall in networkfirewall_client.network_firewalls.items():
            report = Check_Report_AWS(self.metadata())
            report.region = firewall.region
            report.resource_id = firewall.name
            report.resource_arn = arn
            report.resource_tags = firewall.tags
            report.status = "FAIL"
            report.status_extended = f"Network Firewall {firewall.name} default stateless action is not set to drop or forward."

            for action in firewall.default_stateless_frag_actions:
                if action == "aws:drop" or action == "aws:forward_to_sfe":
                    report.status = "PASS"
                    report.status_extended = f"Network Firewall {firewall.name} default stateless action is set to drop or forward."

            findings.append(report)

        return findings
