from lib.check.models import Check, Check_Report
from providers.aws.services.ec2.ec2_client import ec2_client
from providers.aws.services.ec2.lib.network_acls import check_network_acl


class ec2_networkacl_allow_ingress_tcp_port_22(Check):
    def execute(self):
        findings = []
        tcp_protocol = "6"
        check_port = 22
        for network_acl in ec2_client.network_acls:
            public = False
            report = Check_Report(self.metadata)
            report.region = network_acl.region
            for entry in network_acl.entries:
                # For IPv4
                if "CidrBlock" in entry:
                    public = check_network_acl(entry, tcp_protocol, check_port, "IPv4")
                # For IPv6
                if "Ipv6CidrBlock" in entry:
                    public = check_network_acl(entry, tcp_protocol, check_port, "IPv6")
                # If some entry allows it, that ACL is not securely configured
                if public:
                    break
            if not public:
                report.status = "PASS"
                report.status_extended = f"Network ACL {network_acl.id} has not SSH port 22 open to the Internet."
                report.resource_id = network_acl.id
            else:
                report.status = "FAIL"
                report.status_extended = f"Network ACL {network_acl.id} has SSH port 22 open to the Internet."
                report.resource_id = network_acl.id
            findings.append(report)

        return findings
