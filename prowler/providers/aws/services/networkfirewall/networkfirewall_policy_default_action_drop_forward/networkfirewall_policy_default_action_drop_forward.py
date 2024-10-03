from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.networkfirewall.networkfirewall_client import (
    networkfirewall_client,
)


class networkfirewall_policy_default_action_drop_forward(Check):
    def execute(self):
        findings = []
        for arn, firewall in networkfirewall_client.network_firewalls.items():
            report = Check_Report_AWS(self.metadata())
            report.region = firewall.region
            report.resource_id = firewall.name
            report.resource_arn = arn
            report.resource_tags = firewall.tags
            report.status = "FAIL"
            report.status_extended = f"Network Firewall {firewall.name} policy does not drop or forward full packets by default."

            for action in firewall.default_stateless_actions:
                if action == "aws:drop" or action == "aws:forward_to_sfe":
                    report.status = "PASS"
                    report.status_extended = f"Network Firewall {firewall.name} policy does drop or forward full packets by default."

            findings.append(report)

        return findings
