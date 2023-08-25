from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_securitygroup_default_restrict_traffic(Check):
    def execute(self):
        findings = []
        for security_group in ec2_client.security_groups:
            report = Check_Report_AWS(self.metadata())
            report.region = security_group.region
            report.resource_details = security_group.name
            report.resource_id = security_group.id
            report.resource_arn = security_group.arn
            report.resource_tags = security_group.tags
            # Find default security group
            if security_group.name == "default":
                report.status = "FAIL"
                report.status_extended = (
                    f"Default Security Group ({security_group.id}) rules allow traffic."
                )
                if not security_group.ingress_rules and not security_group.egress_rules:
                    report.status = "PASS"
                    report.status_extended = f"Default Security Group ({security_group.id}) rules do not allow traffic."

                findings.append(report)

        return findings
