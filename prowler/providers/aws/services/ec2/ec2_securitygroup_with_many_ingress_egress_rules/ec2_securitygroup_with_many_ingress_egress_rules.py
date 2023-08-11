from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_securitygroup_with_many_ingress_egress_rules(Check):
    def execute(self):
        findings = []

        # max_security_group_rules, default: 50
        max_security_group_rules = ec2_client.audit_config.get(
            "max_security_group_rules", 50
        )
        for security_group in ec2_client.security_groups:
            report = Check_Report_AWS(self.metadata())
            report.region = security_group.region
            report.resource_details = security_group.name
            report.resource_id = security_group.id
            report.resource_arn = security_group.arn
            report.resource_tags = security_group.tags
            report.status = "PASS"
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) has {len(security_group.ingress_rules)} inbound rules and {len(security_group.egress_rules)} outbound rules."
            if (
                len(security_group.ingress_rules) > max_security_group_rules
                or len(security_group.egress_rules) > max_security_group_rules
            ):
                report.status = "FAIL"
            findings.append(report)

        return findings
