from prowler.lib.check.models import Check, CheckReportStackIT
from prowler.providers.stackit.services.iaas.iaas_client import iaas_client


class iaas_security_group_ssh_unrestricted(Check):
    """
    Check if IaaS security groups allow unrestricted SSH access.

    This check verifies that security groups do not allow SSH (port 22)
    access from the public internet (0.0.0.0/0 or ::/0).
    """

    def execute(self):
        """
        Execute the check for all security groups in the StackIT project.

        Returns:
            list: A list of CheckReportStackIT findings
        """
        findings = []

        for security_group in iaas_client.security_groups:
            if not (iaas_client.scan_unused_services or security_group.in_use):
                continue
            report = CheckReportStackIT(
                metadata=self.metadata(),
                resource=security_group,
            )
            report.status = "PASS"
            report.status_extended = f"Security group '{security_group.name}' does not allow unrestricted SSH access."
            report.resource_id = security_group.id
            report.resource_name = security_group.name
            report.location = security_group.region

            for rule in security_group.rules:
                if (
                    rule.is_ingress()
                    and rule.is_tcp()
                    and rule.is_unrestricted()
                    and rule.includes_port(22)
                ):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Security group '{security_group.name}' allows unrestricted SSH access (port 22) "
                        f"from {rule.get_ip_range_display()} via rule {rule.get_rule_display_name()}."
                    )
                    break

            findings.append(report)

        return findings
