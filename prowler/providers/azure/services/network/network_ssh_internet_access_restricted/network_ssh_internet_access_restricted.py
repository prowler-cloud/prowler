from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client
from prowler.providers.azure.services.network.network_service import (
    security_rule_allows_internet,
)


class network_ssh_internet_access_restricted(Check):
    def execute(self) -> Check_Report_Azure:
        """Check whether each security group allows SSH from the Internet.

        Returns:
            One finding per security group. The finding fails when an inbound
            allow rule opens port 22 from Internet, *, or 0.0.0.0/0, including
            a source stored only in source_address_prefixes.
        """
        findings = []
        for subscription, security_groups in network_client.security_groups.items():
            subscription_name = network_client.subscriptions.get(
                subscription, subscription
            )
            for security_group in security_groups:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=security_group
                )
                report.subscription = subscription
                report.status = "PASS"
                report.status_extended = f"Security Group {security_group.name} from subscription {subscription_name} ({subscription}) has SSH internet access restricted."
                rule_fail_condition = any(
                    (
                        rule.destination_port_range == "22"
                        or (
                            (
                                rule.destination_port_range
                                and "-" in rule.destination_port_range
                            )
                            and int(rule.destination_port_range.split("-")[0]) <= 22
                            and int(rule.destination_port_range.split("-")[1]) >= 22
                        )
                    )
                    and rule.protocol in ["TCP", "Tcp", "*"]
                    and security_rule_allows_internet(rule)
                    and rule.access == "Allow"
                    and rule.direction == "Inbound"
                    for rule in security_group.security_rules
                )
                if rule_fail_condition:
                    report.status = "FAIL"
                    report.status_extended = f"Security Group {security_group.name} from subscription {subscription_name} ({subscription}) has SSH internet access allowed."
                findings.append(report)

        return findings
