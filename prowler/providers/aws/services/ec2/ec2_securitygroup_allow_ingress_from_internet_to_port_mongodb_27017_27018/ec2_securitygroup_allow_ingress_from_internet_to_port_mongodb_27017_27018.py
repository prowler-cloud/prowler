from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group


class ec2_securitygroup_allow_ingress_from_internet_to_port_mongodb_27017_27018(Check):
    def execute(self):
        findings = []
        check_ports = [27017, 27018]
        for security_group in ec2_client.security_groups:
            report = Check_Report_AWS(self.metadata())
            report.region = security_group.region
            report.resource_id = security_group.id
            report.resource_arn = security_group.arn
            report.status = "PASS"
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) has not MongoDB ports 27017 and 27018 open to the Internet."
            # Loop through every security group's ingress rule and check it
            for ingress_rule in security_group.ingress_rules:
                if check_security_group(
                    ingress_rule, "tcp", check_ports, any_address=True
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Security group {security_group.name} ({security_group.id}) has MongoDB ports 27017 and 27018 open to the Internet."
                    break
            findings.append(report)

        return findings
