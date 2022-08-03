from lib.check.models import Check, Check_Report
from providers.aws.services.ec2.ec2_service import check_security_group, ec2_client


class ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389(Check):
    def execute(self):
        findings = []
        check_ports = [3389]
        for regional_client in ec2_client.regional_clients:
            region = regional_client.region
            if regional_client.security_groups:
                for security_group in regional_client.security_groups:
                    public = False
                    report = Check_Report(self.metadata)
                    report.region = region
                    # Loop through every security group's ingress rule and check it
                    for ingress_rule in security_group.ingress_rules:
                        public = check_security_group(ingress_rule, "tcp", check_ports)
                    # Check
                    if public:
                        report.status = "FAIL"
                        report.status_extended = f"Security group {security_group.name} ({security_group.id}) has not Microsoft RDP port 3389 open to the Internet."
                        report.resource_id = security_group.id
                    else:
                        report.status = "PASS"
                        report.status_extended = f"Security group {security_group.name} ({security_group.id}) has not Microsoft RDP port 3389 open to the Internet."
                        report.resource_id = security_group.id
                    findings.append(report)
            else:
                report = Check_Report(self.metadata)
                report.status = "PASS"
                report.status_extended = "There are no EC2 security groups."
                report.region = region

                findings.append(report)

        return findings
