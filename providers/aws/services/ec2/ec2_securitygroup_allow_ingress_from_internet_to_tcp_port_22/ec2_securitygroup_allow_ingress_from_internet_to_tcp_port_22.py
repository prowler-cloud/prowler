from lib.check.models import Check, Check_Report
from providers.aws.services.ec2.ec2_service import check_security_group, ec2_client


class ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22(Check):
    def execute(self):
        findings = []
        check_ports = [22]
        for security_group in ec2_client.security_groups:
            public = False
            report = Check_Report(self.metadata)
            report.region = security_group.region
            # Loop through every security group's ingress rule and check it
            for ingress_rule in security_group.ingress_rules:
                public = check_security_group(ingress_rule, "tcp", check_ports)
                # Check
                if public:
                    report.status = "FAIL"
                    report.status_extended = f"Security group {security_group.name} ({security_group.id}) has the SSH port 22 open to the Internet."
                    report.resource_id = security_group.id
                else:
                    report.status = "PASS"
                    report.status_extended = f"Security group {security_group.name} ({security_group.id}) has not SSH port 22 open to the Internet."
                    report.resource_id = security_group.id
                findings.append(report)

        return findings
