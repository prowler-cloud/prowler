from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_udp_internet_access_restricted(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        if network_client.security_groups is not None:
            for subscription, security_groups in network_client.security_groups.items():
                for security_group in security_groups:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=security_group
                    )
                    report.subscription = subscription
                    report.status = "PASS"
                    report.status_extended = f"Security Group {security_group.name} from subscription {subscription} has UDP internet access restricted."
                    rule_fail_condition = any(
                        rule.protocol in ["UDP", "Udp"]
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
