from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group


class ec2_securitygroup_default_restrict_traffic(Check):
    def execute(self):
        findings = []
        for security_group in ec2_client.security_groups:
            report = Check_Report_AWS(self.metadata())
            report.region = security_group.region
            report.resource_id = security_group.id
            report.resource_arn = security_group.arn
            # Find default security group
            if security_group.name == "default":
                report.status = "PASS"
                report.status_extended = f"Default Security Group ({security_group.id}) is not open to the Internet."
                for ingress_rule in security_group.ingress_rules:
                    if check_security_group(ingress_rule, "-1", any_address=True):
                        report.status = "FAIL"
                        report.status_extended = f"Default Security Group ({security_group.id}) is open to the Internet."
                        break
                findings.append(report)

        return findings
