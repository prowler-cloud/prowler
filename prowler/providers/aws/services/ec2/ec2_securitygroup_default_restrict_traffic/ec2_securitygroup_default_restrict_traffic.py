from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import (
    is_changed_default_security_group,
)


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
                report.status = "PASS"
                report.status_extended = f"Default Security Group ({security_group.id}) rules have not being changed and restrict all the traffic."
                if (
                    len(security_group.ingress_rules) > 1
                    or len(security_group.egress_rules) > 1
                    or (
                        security_group.ingress_rules
                        and security_group.egress_rules
                        and is_changed_default_security_group(
                            security_group.ingress_rules[0],
                            security_group.egress_rules[0],
                        )
                    )
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Default Security Group ({security_group.id}) rules have being changed and don't restrict all the traffic."

                findings.append(report)

        return findings
