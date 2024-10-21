from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client

class ec2_restricted_common_ports(Check):
    def execute(self):
        findings = []
        common_ports = [22, 80, 443]        

        for arn, sg in ec2_client.security_groups.items():
            report = Check_Report_AWS(self.metadata())
            report.region = sg.region
            report.resource_id = sg.id
            report.resource_arn = arn
            report.resource_tags = sg.tags

            non_compliant_ports = []
            
            for rule in sg.ingress_rules:
                if rule.get("IpProtocol") == "tcp":
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")

                    if from_port in common_ports or to_port in common_ports:
                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                non_compliant_ports.append(from_port)
                        for ipv6_range in rule.get("Ipv6Ranges", []):
                            if ipv6_range.get("CidrIpv6") == "::/0":
                                non_compliant_ports.append(from_port)

            if non_compliant_ports:
                report.status = "FAIL"
                report.status_extended = f"Security group {sg.id} allows unrestricted TCP traffic to ports: {non_compliant_ports}."
            else:
                report.status = "PASS"
                report.status_extended = f"Security group {sg.id} does not allow unrestricted TCP traffic to common ports."

            findings.append(report)

        return findings
