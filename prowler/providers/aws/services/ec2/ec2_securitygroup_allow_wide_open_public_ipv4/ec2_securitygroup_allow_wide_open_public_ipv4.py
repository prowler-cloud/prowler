import ipaddress

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_securitygroup_allow_wide_open_public_ipv4(Check):
    def execute(self):
        findings = []
        cidr_treshold = 24
        for security_group in ec2_client.security_groups:
            report = Check_Report_AWS(self.metadata())
            report.region = security_group.region
            report.resource_id = security_group.id
            report.status = "PASS"
            report.status_extended = f"Security group {security_group.name} ({security_group.id}) has no potential wide-open non-RFC1918 address."
            # Loop through every security group's ingress rule and check it
            for ingress_rule in security_group.ingress_rules:
                for ipv4 in ingress_rule["IpRanges"]:
                    ip = ipaddress.ip_network(ipv4["CidrIp"])
                    # Check if IP is public according to RFC1918 and if 0 < prefixlen < 24
                    if (
                        ip.is_global
                        and ip.prefixlen < cidr_treshold
                        and ip.prefixlen > 0
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"Security group {security_group.name} ({security_group.id}) has potential wide-open non-RFC1918 address {ipv4['CidrIp']} in ingress rule."
                        break

            # Loop through every security group's egress rule and check it
            for egress_rule in security_group.egress_rules:
                for ipv4 in egress_rule["IpRanges"]:
                    ip = ipaddress.ip_network(ipv4["CidrIp"])
                    # Check if IP is public according to RFC1918 and if 0 < prefixlen < 24
                    if (
                        ip.is_global
                        and ip.prefixlen < cidr_treshold
                        and ip.prefixlen > 0
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"Security group {security_group.name} ({security_group.id}) has potential wide-open non-RFC1918 address {ipv4['CidrIp']} in egress rule."
                        break

            findings.append(report)

        return findings
