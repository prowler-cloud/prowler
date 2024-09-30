from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.networkfirewall.networkfirewall_client import (
    networkfirewall_client,
)


class networkfirewall_policy_rule_group_associated(Check):
    def execute(self):
        findings = []
        for firewall in networkfirewall_client.network_firewalls.values():
            report = Check_Report_AWS(self.metadata())
            report.region = firewall.region
            report.resource_id = firewall.name
            report.resource_arn = firewall.arn
            report.resource_tags = firewall.tags
            report.status = "PASS"
            report.status_extended = f"Network Firewall {firewall.name} policy has at least one rule group associated."

            if not firewall.stateful_rule_groups and not firewall.stateless_rule_groups:
                report.status = "FAIL"
                report.status_extended = f"Network Firewall {firewall.name} policy does not have rule groups associated."

            findings.append(report)

        return findings
