from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_securitygroup_not_used(Check):
    def execute(self):
        findings = []
        for security_group in ec2_client.security_groups:
            report = Check_Report_AWS(self.metadata())
            report.region = security_group.region
            report.resource_id = security_group.id
            report.status = "PASS"
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) it is being used."
            if len(security_group.network_interfaces) == 0:
                report.status = "FAIL"
                report.status_extended = f"Security group {security_group.name} ({security_group.id}) it is not being used."

            findings.append(report)

        return findings
