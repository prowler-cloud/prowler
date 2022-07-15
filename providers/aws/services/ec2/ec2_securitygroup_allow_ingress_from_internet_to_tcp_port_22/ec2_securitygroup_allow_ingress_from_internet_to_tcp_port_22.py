from lib.check.models import Check, Check_Report
from providers.aws.services.ec2.ec2_service import ec2_client


class ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22(Check):
    def execute(self):
        findings = []
        check_port = 22
        for regional_client in ec2_client.regional_clients:
            region = regional_client.region
            if regional_client.security_groups:
                for security_group in regional_client.security_groups:
                    public = False
                    report = Check_Report(self.metadata)
                    report.region = region
                    for ingress_rule in security_group.ingress_rules:
                        if (
                            "0.0.0.0/0" in str(ingress_rule["IpRanges"])
                            or "::/0" in str(ingress_rule["Ipv6Ranges"])
                        ) and (
                            ingress_rule["FromPort"] == check_port
                            and ingress_rule["ToPort"] == check_port
                        ):
                            public = True
                            report.status = "FAIL"
                            report.status_extended = f"Security group {security_group.name} ({security_group.id}) has the SSH port 22 open to the Internet."
                            report.resource_id = security_group.id
                    if not public:
                        report.status = "PASS"
                        report.status_extended = f"Security group {security_group.name} ({security_group.id}) has not SSH port 22 open to the Internet."
                        report.resource_id = security_group.id
                    findings.append(report)
            else:
                report = Check_Report(self.metadata)
                report.status = "PASS"
                report.status_extended = "There are no EC2 security groups."
                report.region = region

                findings.append(report)

        return findings
