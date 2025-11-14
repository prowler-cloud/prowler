from prowler.lib.check.models import Check, CheckReportStackIT
from prowler.providers.stackit.services.iaas.iaas_client import iaas_client


class iaas_security_group_all_traffic_unrestricted(Check):
    """
    Check if IaaS security groups allow unrestricted access to all traffic.

    This check verifies that security groups do not allow all traffic
    (all ports and protocols) from the public internet (0.0.0.0/0 or ::/0).
    """

    def execute(self):
        """
        Execute the check for all security groups in the StackIT project.

        Returns:
            list: A list of CheckReportStackIT findings
        """
        findings = []

        for security_group in iaas_client.security_groups:
            unrestricted_rules = []

            # Check each ingress rule
            for rule in security_group.rules:
                # Only check ingress rules that are unrestricted
                if rule.is_ingress() and rule.is_unrestricted():
                    # Check if rule allows all traffic (no port restrictions or all protocols)
                    if rule.port_range_min is None or rule.port_range_max is None:
                        # No port range specified - allows all ports
                        unrestricted_rules.append(
                            f"Rule '{rule.id}' allows all ports ({rule.protocol}) from {rule.ip_range}"
                        )
                    elif (
                        rule.port_range_min == 0
                        or rule.port_range_min == 1
                    ) and rule.port_range_max >= 65535:
                        # Port range covers all or nearly all ports
                        unrestricted_rules.append(
                            f"Rule '{rule.id}' allows all ports (1-65535) ({rule.protocol}) from {rule.ip_range}"
                        )

            # Create a finding report for this security group
            report = CheckReportStackIT(
                metadata=self.metadata(),
                resource=security_group,
            )

            if unrestricted_rules:
                report.status = "FAIL"
                rules_list = "; ".join(unrestricted_rules)
                report.status_extended = (
                    f"Security group '{security_group.name}' allows unrestricted access to all traffic: {rules_list}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Security group '{security_group.name}' does not allow unrestricted access to all traffic."
                )

            report.resource_id = security_group.id
            report.resource_name = security_group.name
            report.location = security_group.region

            findings.append(report)

        return findings
