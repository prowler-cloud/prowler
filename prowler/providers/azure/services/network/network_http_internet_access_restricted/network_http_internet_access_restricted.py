from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_http_internet_access_restricted(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, security_groups in network_client.security_groups.items():
            for security_group in security_groups:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = security_group.name
                report.resource_id = security_group.id
                report.status = "PASS"
                report.status_extended = f"Security Group {security_group.name} from subscription {subscription} has UDP internet access restricted."
                rule_fail_condition = any(
                    rule.destination_port_range == "80"
                    and rule.protocol in ["TCP", "*"]
                    and rule.source_address_prefix in ["Internet", "*", "0.0.0.0/0"]
                    and rule.access == "Allow"
                    and rule.direction == "Inbound"
                    for rule in security_group.security_rules
                )
                if rule_fail_condition:
                    report.status = "FAIL"
                    report.status_extended = f"Security Group {security_group.name} from subscription {subscription} has UDP internet access allowed."
                findings.append(report)

        return findings
