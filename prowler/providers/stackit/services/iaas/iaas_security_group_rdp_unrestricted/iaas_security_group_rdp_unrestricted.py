from prowler.lib.check.models import Check, CheckReportStackIT
from prowler.providers.stackit.services.iaas.iaas_client import iaas_client


class iaas_security_group_rdp_unrestricted(Check):
    """
    Check if IaaS security groups allow unrestricted RDP access.

    This check verifies that security groups do not allow RDP (port 3389)
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
            # Only check security groups that are actively in use
            if not security_group.in_use:
                continue
            # Check each ingress rule
            for rule in security_group.rules:
                # Only check ingress TCP rules that are unrestricted
                if rule.is_ingress() and rule.is_tcp() and rule.is_unrestricted():
                    # Check if rule allows RDP (port 3389)
                    if rule.includes_port(3389):
                        # Create a finding report for this security group
                        report = CheckReportStackIT(
                            metadata=self.metadata(),
                            resource=security_group,
                        )

                        report.status = "FAIL"
                        report.status_extended = (
                            f"Security group '{security_group.name}' allows unrestricted RDP access (port 3389) "
                            f"from {rule.get_ip_range_display()} via rule '{rule.id}'."
                        )
                        report.resource_id = security_group.id
                        report.resource_name = security_group.name
                        report.location = security_group.region

                        findings.append(report)
                        # Only report once per security group
                        break
            else:
                # No unrestricted RDP rule found - PASS
                report = CheckReportStackIT(
                    metadata=self.metadata(),
                    resource=security_group,
                )

                report.status = "PASS"
                report.status_extended = f"Security group '{security_group.name}' does not allow unrestricted RDP access."
                report.resource_id = security_group.id
                report.resource_name = security_group.name
                report.location = security_group.region

                findings.append(report)

        return findings
