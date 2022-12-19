from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.network_acls import check_network_acl


class ec2_networkacl_allow_ingress_tcp_port_3389(Check):
    def execute(self):
        findings = []
        tcp_protocol = "6"
        check_port = 3389
        for network_acl in ec2_client.network_acls:
            report = Check_Report_AWS(self.metadata())
            report.region = network_acl.region
            # If some entry allows it, that ACL is not securely configured
            if not check_network_acl(network_acl.entries, tcp_protocol, check_port):
                report.status = "PASS"
                report.status_extended = f"Network ACL {network_acl.id} has not Microsoft RDP port 3389 open to the Internet."
                report.resource_id = network_acl.id
            else:
                report.status = "FAIL"
                report.status_extended = f"Network ACL {network_acl.id} has Microsoft RDP port 3389 open to the Internet."
                report.resource_id = network_acl.id
            findings.append(report)

        return findings
