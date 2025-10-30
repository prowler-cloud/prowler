from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client


class ecs_instance_ssh_access_restricted(Check):
    def execute(self):
        findings = []
        for security_group in ecs_client.security_groups.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=security_group
            )
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
            report.status = "FAIL"
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) allows unrestricted SSH access."
            if not has_unrestricted_ssh:
                report.status = "PASS"
                report.status_extended = f"Security group {security_group.name} ({security_group.id}) does not allow unrestricted SSH access."
            findings.append(report)
        return findings
