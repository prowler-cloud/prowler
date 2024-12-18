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
                report.location = security_group.location
                report.status_extended = f"Security Group {security_group.name} from subscription {subscription} has HTTP internet access restricted."
                rule_fail_condition = any(
                    (
                        getattr(rule, "destination_port_range", "") == "80"
                        or (
                            "-" in getattr(rule, "destination_port_range", "")
                            and int(
                                getattr(rule, "destination_port_range", "0-0").split(
                                    "-"
                                )[0]
                            )
                            <= 80
                            and int(
                                getattr(rule, "destination_port_range", "0-0").split(
                                    "-"
                                )[1]
                            )
                            >= 80
                        )
                    )
                    and getattr(rule, "protocol", "").lower() in ["tcp", "*"]
                    and getattr(rule, "source_address_prefix", "")
                    in ["Internet", "*", "0.0.0.0/0"]
                    and getattr(rule, "access", "") == "Allow"
                    and getattr(rule, "direction", "") == "Inbound"
                    for rule in getattr(security_group, "security_rules", []) or []
                )
                if rule_fail_condition:
                    report.status = "FAIL"
                    report.status_extended = f"Security Group {security_group.name} from subscription {subscription} has HTTP internet access allowed."
                findings.append(report)

        return findings
