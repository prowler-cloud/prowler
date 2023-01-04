from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group


class ec2_securitygroup_in_use_without_ingress_filtering(Check):
    def execute(self):
        findings = []
        for security_group in ec2_client.security_groups:
            report = Check_Report_AWS(self.metadata())
            report.region = security_group.region
            report.resource_id = security_group.id
            report.resource_arn = security_group.arn
            report.status = "PASS"
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) has ingress filtering."
            for ingress_rule in security_group.ingress_rules:
                if check_security_group(ingress_rule, "-1"):
                    report.status = "FAIL"
                    if len(security_group.network_interfaces) > 0:
                        report.status_extended = f"Security group {security_group.name} ({security_group.id}) has no ingress filtering and it is being used."
                    else:
                        report.status_extended = f"Security group {security_group.name} ({security_group.id}) has no ingress filtering and it is not being used."
                    break

            findings.append(report)

        return findings
