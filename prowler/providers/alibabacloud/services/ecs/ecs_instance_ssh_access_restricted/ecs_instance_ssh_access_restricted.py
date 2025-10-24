from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client


class ecs_instance_ssh_access_restricted(Check):
    """
    Check if ECS security groups restrict SSH access from the internet

    This check ensures that security groups associated with ECS instances
    do not allow unrestricted SSH access (0.0.0.0/0) on port 22.

    Risk: Unrestricted SSH access can lead to unauthorized access attempts
    and potential security breaches.

    Recommendation: Restrict SSH access to specific IP addresses or ranges.
    """

    def execute(self):
        """Execute the check"""
        findings = []

        # Iterate through all security groups
        for sg_arn, security_group in ecs_client.security_groups.items():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=security_group
            )
            report.account_uid = ecs_client.account_id
            report.region = security_group.region
            report.resource_id = security_group.id
            report.resource_arn = security_group.arn

            # Check for unrestricted SSH access
            has_unrestricted_ssh = False
            for rule in security_group.rules:
                if (
                    rule.get("direction") == "ingress"
                    and rule.get("protocol") == "tcp"
                    and "22" in rule.get("port_range", "")
                    and rule.get("source") == "0.0.0.0/0"
                ):
                    has_unrestricted_ssh = True
                    break

            if has_unrestricted_ssh:
                report.status = "FAIL"
                report.status_extended = (
                    f"Security group {security_group.name} ({security_group.id}) "
                    f"allows unrestricted SSH access from the internet (0.0.0.0/0)."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Security group {security_group.name} ({security_group.id}) "
                    f"does not allow unrestricted SSH access from the internet."
                )

            findings.append(report)

        return findings
