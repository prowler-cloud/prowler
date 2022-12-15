from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_securitygroup_from_launch_wizard(Check):
    def execute(self):
        findings = []
        for security_group in ec2_client.security_groups:
            report = Check_Report_AWS(self.metadata())
            report.region = security_group.region
            report.resource_id = security_group.id
            report.status = "PASS"
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) was not created using the EC2 Launch Wizard."
            if "launch-wizard" in security_group.name:
                report.status = "FAIL"
                report.status_extended = f"Security group {security_group.name} ({security_group.id}) was created using the EC2 Launch Wizard."

            findings.append(report)

        return findings
