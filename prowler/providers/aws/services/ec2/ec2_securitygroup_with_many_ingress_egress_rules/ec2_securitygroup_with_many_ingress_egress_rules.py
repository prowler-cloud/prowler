from prowler.config.config import get_config_var
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_securitygroup_with_many_ingress_egress_rules(Check):
    def execute(self):
        findings = []
        max_security_group_rules = get_config_var("max_security_group_rules")
        for security_group in ec2_client.security_groups:
            report = Check_Report_AWS(self.metadata())
            report.region = security_group.region
            report.resource_id = security_group.id
            report.resource_arn = security_group.arn
            report.status = "PASS"
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) has {len(security_group.ingress_rules)} inbound rules and {len(security_group.egress_rules)} outbound rules"
            if (
                len(security_group.ingress_rules) > max_security_group_rules
                or len(security_group.egress_rules) > max_security_group_rules
            ):
                report.status = "FAIL"
            findings.append(report)

        return findings
