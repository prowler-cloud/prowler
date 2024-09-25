from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.networkfirewall.networkfirewall_client import (
    networkfirewall_client,
)
from prowler.providers.aws.services.networkfirewall.networkfirewall_service import (
    LogType,
)


class networkfirewall_logging_enabled(Check):
    def execute(self):
        findings = []
        for arn, firewall in networkfirewall_client.network_firewalls.items():
            report = Check_Report_AWS(self.metadata())
            report.region = firewall.region
            report.resource_id = firewall.name
            report.resource_arn = arn
            report.resource_tags = firewall.tags
            report.status = "FAIL"
            report.status_extended = f"Network Firewall {firewall.name} does not have logging enabled in any destination."

            for configuration in firewall.logging_configuration:
                if (
                    configuration.log_type in LogType
                    and configuration.log_destination != {}
                ):
                    report.status = "PASS"
                    report.status_extended = f"Network Firewall {firewall.name} has logging enabled in at least one destination."
                    break

            findings.append(report)

        return findings
